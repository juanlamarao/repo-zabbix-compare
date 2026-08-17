from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from .collector import new_endpoint, old_endpoint
from .config import get_settings
from .db import get_pool
from .zabbix import ZabbixClient

router = APIRouter(prefix="/api")


class BaselineCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)


class ExpectedChangeIn(BaseModel):
    object_type: str
    object_id: int
    field: str
    note: str | None = None
    enabled: bool = True


@router.get("/health")
async def health():
    return {"status": "ok"}


@router.get("/config")
async def config():
    settings = get_settings()
    return {
        "hosts_per_batch": settings.hosts_per_batch,
        "parallel_batches": settings.parallel_batches,
        "collection_interval_seconds": settings.collection_interval_seconds,
        "old_url_configured": bool(settings.old_zabbix_url),
        "new_url_configured": bool(settings.new_zabbix_url),
    }


@router.get("/zabbix/test")
async def test_zabbix():
    result = {}
    for name, endpoint in (("old", old_endpoint()), ("new", new_endpoint())):
        if not endpoint.url:
            result[name] = {"ok": False, "error": "URL não configurada"}
            continue
        client = ZabbixClient(endpoint)
        try:
            result[name] = {"ok": True, "version": await client.version()}
        except Exception as exc:
            result[name] = {"ok": False, "error": str(exc)}
        finally:
            await client.close()
    return result


@router.post("/baselines")
async def create_baseline(body: BaselineCreate):
    pool = await get_pool()
    async with pool.acquire() as conn:
        existing = await conn.fetchval(
            "SELECT count(*) FROM baselines WHERE status IN ('REQUESTED','COLLECTING')"
        )
        if existing:
            raise HTTPException(409, "Já existe uma fotografia em coleta.")
        row = await conn.fetchrow(
            "INSERT INTO baselines(name,status) VALUES($1,'REQUESTED') RETURNING *", body.name
        )
        return dict(row)


@router.get("/baselines")
async def list_baselines():
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch("SELECT * FROM baselines ORDER BY created_at DESC LIMIT 20")
        return [dict(row) for row in rows]


@router.post("/baselines/{baseline_id}/freeze")
async def freeze_baseline(baseline_id: UUID):
    pool = await get_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            status = await conn.fetchval(
                "SELECT status FROM baselines WHERE id=$1 FOR UPDATE", baseline_id
            )
            if status != "READY":
                raise HTTPException(409, "A baseline precisa estar READY para ser congelada.")
            await conn.execute(
                "UPDATE baselines SET status='FROZEN',frozen_at=now() WHERE id=$1", baseline_id
            )
            await conn.execute(
                "UPDATE baselines SET status='ARCHIVED' WHERE id<>$1 AND status='FROZEN'", baseline_id
            )
            await conn.execute(
                """
                INSERT INTO app_meta(key,value) VALUES('active_slot','0'::jsonb)
                ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value,updated_at=now()
                """
            )
        return {"ok": True}


@router.post("/cycles/run")
async def force_cycle():
    settings = get_settings()
    if not settings.new_zabbix_url or not settings.new_zabbix_token:
        raise HTTPException(409, "Zabbix 7 ainda não está configurado. A baseline permanece congelada e aguardando o destino.")
    pool = await get_pool()
    async with pool.acquire() as conn:
        active = await conn.fetchval("SELECT count(*) FROM baselines WHERE status='FROZEN'")
        if not active:
            raise HTTPException(409, "Nenhuma baseline congelada.")
        running = await conn.fetchval("SELECT count(*) FROM cycles WHERE status='RUNNING'")
        if running:
            return {"ok": True, "message": "Já existe um ciclo em andamento."}
        await conn.execute(
            """
            INSERT INTO app_meta(key,value) VALUES('force_cycle','true'::jsonb)
            ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value,updated_at=now()
            """
        )
        return {"ok": True}


@router.get("/dashboard")
async def dashboard():
    pool = await get_pool()
    async with pool.acquire() as conn:
        baseline = await conn.fetchrow(
            "SELECT * FROM baselines WHERE status='FROZEN' ORDER BY frozen_at DESC LIMIT 1"
        )
        running = None
        complete = None
        if baseline:
            running = await conn.fetchrow(
                "SELECT * FROM cycles WHERE baseline_id=$1 AND status='RUNNING' ORDER BY started_at DESC LIMIT 1", baseline["id"]
            )
            complete = await conn.fetchrow(
                "SELECT * FROM cycles WHERE baseline_id=$1 AND status='COMPLETE' ORDER BY finished_at DESC LIMIT 1", baseline["id"]
            )
        alerts = []
        if complete:
            alerts = [
                dict(row)
                for row in await conn.fetch(
                    """
                    SELECT * FROM change_events WHERE cycle_id=$1
                    ORDER BY CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 ELSE 3 END,id
                    LIMIT 50
                    """,
                    complete["id"],
                )
            ]
        return {
            "baseline": dict(baseline) if baseline else None,
            "running_cycle": dict(running) if running else None,
            "last_cycle": dict(complete) if complete else None,
            "alerts": alerts,
        }


@router.get("/cycles/history")
async def cycle_history(limit: int = Query(50, ge=1, le=500)):
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT id,status,started_at,finished_at,hosts_total,hosts_processed,metrics,error
            FROM cycles ORDER BY started_at DESC LIMIT $1
            """,
            limit,
        )
        return [dict(row) for row in rows]


@router.get("/lld/regressions")
async def lld_regressions(limit: int = Query(200, ge=1, le=2000)):
    pool = await get_pool()
    async with pool.acquire() as conn:
        baseline = await conn.fetchval(
            "SELECT id FROM baselines WHERE status='FROZEN' ORDER BY frozen_at DESC LIMIT 1"
        )
        slot = await conn.fetchval(
            "SELECT COALESCE((SELECT (value #>> '{}')::int FROM app_meta WHERE key='active_slot'),0)"
        )
        if not baseline:
            return []
        rows = await conn.fetch(
            """
            SELECT l.itemid AS lldid,l.name,l.hostid,l.lifetime AS baseline_lifetime,
                   c.lifetime AS current_lifetime,c.lifetime_type,c.enabled_lifetime,c.enabled_lifetime_type,
                   b.object_kind,b.prototype_id,b.eligible_children,
                   COALESCE(s.existing_children,0) AS existing_children,
                   COALESCE(s.discovered_children,0) AS discovered_children,
                   COALESCE(s.lost_children,0) AS lost_children,
                   COALESCE(s.scheduled_delete,0) AS scheduled_delete,
                   COALESCE(s.scheduled_disable,0) AS scheduled_disable,
                   CASE WHEN COALESCE(s.discovered_children,0)=0 THEN 'CRITICAL'
                        WHEN COALESCE(s.discovered_children,0)<b.eligible_children THEN 'WARNING'
                        ELSE 'OK' END AS result
            FROM baseline_lld_child_stats b
            JOIN baseline_llds l ON l.baseline_id=b.baseline_id AND l.itemid=b.lldid
            LEFT JOIN state_llds c ON c.slot=$2 AND c.itemid=b.lldid
            LEFT JOIN state_lld_child_stats s
              ON s.slot=$2 AND s.lldid=b.lldid
             AND s.object_kind=b.object_kind AND s.prototype_id=b.prototype_id
            WHERE b.baseline_id=$1 AND b.eligible_children>0
              AND COALESCE(s.discovered_children,0)<b.eligible_children
            ORDER BY CASE WHEN COALESCE(s.discovered_children,0)=0 THEN 0 ELSE 1 END,
                     (b.eligible_children-COALESCE(s.discovered_children,0)) DESC
            LIMIT $3
            """,
            baseline, int(slot or 0), limit,
        )
        return [dict(row) for row in rows]


@router.get("/items/regressions")
async def item_regressions(
    kind: str = "problem",
    limit: int = Query(500, ge=1, le=5000),
    offset: int = Query(0, ge=0),
):
    pool = await get_pool()
    async with pool.acquire() as conn:
        baseline = await conn.fetchval(
            "SELECT id FROM baselines WHERE status='FROZEN' ORDER BY frozen_at DESC LIMIT 1"
        )
        slot = await conn.fetchval(
            "SELECT COALESCE((SELECT (value #>> '{}')::int FROM app_meta WHERE key='active_slot'),0)"
        )
        if not baseline:
            return []
        rows = await conn.fetch(
            """
            SELECT b.itemid,b.hostid,b.name,b.key_,b.lastclock AS baseline_lastclock,
                   s.lastclock,s.state,s.error,s.discovery_status,s.ts_delete,s.ts_disable,
                   CASE
                     WHEN s.itemid IS NULL THEN 'MISSING'
                     WHEN COALESCE(s.discovery_status,0)=1 OR COALESCE(s.ts_delete,0)>0 THEN 'LLD_LOST'
                     WHEN s.state<>0 OR COALESCE(s.error,'')<>'' THEN 'UNSUPPORTED'
                     WHEN s.lastclock<=COALESCE(b.lastclock,0) THEN 'PENDING'
                     ELSE 'OK'
                   END AS result
            FROM baseline_items b
            LEFT JOIN state_items s ON s.slot=$2 AND s.itemid=b.itemid
            WHERE b.baseline_id=$1 AND b.eligible
              AND (
                $3='all'
                OR ($3='problem' AND (
                    s.itemid IS NULL OR s.state<>0 OR COALESCE(s.error,'')<>''
                    OR COALESCE(s.discovery_status,0)=1 OR COALESCE(s.ts_delete,0)>0
                ))
                OR ($3='pending' AND s.itemid IS NOT NULL AND s.state=0 AND COALESCE(s.error,'')=''
                    AND COALESCE(s.discovery_status,0)=0 AND COALESCE(s.ts_delete,0)=0
                    AND s.lastclock<=COALESCE(b.lastclock,0))
              )
            ORDER BY b.hostid,b.itemid LIMIT $4 OFFSET $5
            """,
            baseline, int(slot or 0), kind, limit, offset,
        )
        return [dict(row) for row in rows]


@router.get("/proxies")
async def proxies():
    pool = await get_pool()
    async with pool.acquire() as conn:
        baseline = await conn.fetchval(
            "SELECT id FROM baselines WHERE status='FROZEN' ORDER BY frozen_at DESC LIMIT 1"
        )
        slot = await conn.fetchval(
            "SELECT COALESCE((SELECT (value #>> '{}')::int FROM app_meta WHERE key='active_slot'),0)"
        )
        if not baseline:
            return []
        rows = await conn.fetch(
            """
            SELECT b.proxyid,b.name AS baseline_name,s.name AS current_name,
                   b.lastaccess AS baseline_lastaccess,s.lastaccess AS current_lastaccess,
                   s.version,s.compatibility,s.state,
                   (b.name IS DISTINCT FROM s.name) AS name_changed,
                   EXISTS(
                     SELECT 1 FROM expected_changes e
                     WHERE e.enabled AND e.object_type='proxy' AND e.object_id=b.proxyid AND e.field='name'
                   ) AS name_change_expected,
                   (SELECT count(*) FROM baseline_hosts h
                    WHERE h.baseline_id=b.baseline_id AND h.proxyid=b.proxyid) AS hosts,
                   (SELECT count(*) FROM baseline_items bi
                    WHERE bi.baseline_id=b.baseline_id AND bi.proxyid=b.proxyid AND bi.eligible) AS items_total,
                   (SELECT count(*) FROM baseline_items bi
                    JOIN state_items si ON si.slot=$2 AND si.itemid=bi.itemid
                    WHERE bi.baseline_id=b.baseline_id AND bi.proxyid=b.proxyid AND bi.eligible
                      AND si.state=0 AND COALESCE(si.error,'')=''
                      AND si.lastclock>COALESCE(bi.lastclock,0)) AS items_ok
            FROM baseline_proxies b
            LEFT JOIN state_proxies s ON s.slot=$2 AND s.proxyid=b.proxyid
            WHERE b.baseline_id=$1 ORDER BY b.name
            """,
            baseline, int(slot or 0),
        )
        return [dict(row) for row in rows]


@router.get("/expected-changes")
async def expected_changes():
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT * FROM expected_changes ORDER BY object_type,object_id,field"
        )
        return [dict(row) for row in rows]


@router.post("/expected-changes")
async def upsert_expected_change(body: ExpectedChangeIn):
    if body.object_type not in {"proxy", "action", "media_type"}:
        raise HTTPException(422, "object_type inválido")
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO expected_changes(object_type,object_id,field,note,enabled)
            VALUES($1,$2,$3,$4,$5)
            ON CONFLICT(object_type,object_id,field)
            DO UPDATE SET note=EXCLUDED.note,enabled=EXCLUDED.enabled
            RETURNING *
            """,
            body.object_type, body.object_id, body.field, body.note, body.enabled,
        )
        return dict(row)

@router.get("/actions")
async def actions():
    pool = await get_pool()
    async with pool.acquire() as conn:
        baseline = await conn.fetchval(
            "SELECT id FROM baselines WHERE status='FROZEN' ORDER BY frozen_at DESC LIMIT 1"
        )
        slot = await conn.fetchval(
            "SELECT COALESCE((SELECT (value #>> '{}')::int FROM app_meta WHERE key='active_slot'),0)"
        )
        if not baseline:
            return []
        rows = await conn.fetch(
            """
            SELECT b.actionid,b.name,b.status AS baseline_status,s.status AS current_status,
                   EXISTS(
                     SELECT 1 FROM expected_changes e
                     WHERE e.enabled AND e.object_type='action' AND e.object_id=b.actionid AND e.field='status'
                   ) AS status_change_expected
            FROM baseline_actions b
            LEFT JOIN state_actions s ON s.slot=$2 AND s.actionid=b.actionid
            WHERE b.baseline_id=$1 AND b.eligible ORDER BY b.name
            """,
            baseline, int(slot or 0),
        )
        result = []
        for row in rows:
            item = dict(row)
            item["baseline_runs"] = [
                dict(r) for r in await conn.fetch(
                    "SELECT rank,eventid,clock,summary_status FROM baseline_action_runs WHERE baseline_id=$1 AND actionid=$2 ORDER BY rank",
                    baseline, row["actionid"],
                )
            ]
            item["current_runs"] = [
                dict(r) for r in await conn.fetch(
                    "SELECT rank,eventid,clock,summary_status FROM state_action_runs WHERE slot=$1 AND actionid=$2 ORDER BY rank",
                    int(slot or 0), row["actionid"],
                )
            ]
            result.append(item)
        return result


@router.get("/media-types")
async def media_types():
    pool = await get_pool()
    async with pool.acquire() as conn:
        baseline = await conn.fetchval(
            "SELECT id FROM baselines WHERE status='FROZEN' ORDER BY frozen_at DESC LIMIT 1"
        )
        slot = await conn.fetchval(
            "SELECT COALESCE((SELECT (value #>> '{}')::int FROM app_meta WHERE key='active_slot'),0)"
        )
        if not baseline:
            return []
        rows = await conn.fetch(
            """
            SELECT b.mediatypeid,b.name,b.type,b.status AS baseline_status,s.status AS current_status,
                   EXISTS(
                     SELECT 1 FROM expected_changes e
                     WHERE e.enabled AND e.object_type='media_type' AND e.object_id=b.mediatypeid AND e.field='status'
                   ) AS status_change_expected
            FROM baseline_media_types b
            LEFT JOIN state_media_types s ON s.slot=$2 AND s.mediatypeid=b.mediatypeid
            WHERE b.baseline_id=$1 AND b.eligible ORDER BY b.name
            """,
            baseline, int(slot or 0),
        )
        return [dict(row) for row in rows]
