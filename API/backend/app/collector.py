from __future__ import annotations

import asyncio
import json
from uuid import UUID

from .config import get_settings
from .db import get_pool
from .zabbix import ZabbixClient, ZabbixEndpoint
from .normalizers import as_int, summarize_action_runs
from .storage import (
    clear_slot,
    insert_baseline_batch,
    insert_baseline_globals,
    insert_baseline_hosts,
    insert_state_batch,
    insert_state_globals,
    insert_state_hosts,
    rebuild_baseline_lld_stats,
    rebuild_state_lld_stats,
)
from .comparison import build_change_events, compute_metrics


def chunks(values: list[int], size: int):
    for pos in range(0, len(values), size):
        yield values[pos : pos + size]


def old_endpoint() -> ZabbixEndpoint:
    s = get_settings()
    return ZabbixEndpoint(
        s.old_zabbix_url, s.old_zabbix_token, s.verify_ssl,
        s.request_timeout_seconds, s.api_retries,
    )


def new_endpoint() -> ZabbixEndpoint:
    s = get_settings()
    return ZabbixEndpoint(
        s.new_zabbix_url, s.new_zabbix_token, s.verify_ssl,
        s.request_timeout_seconds, s.api_retries,
    )


async def collect_action_runs(
    client: ZabbixClient, actions: list[dict], limit: int, time_from: int | None = None
) -> dict[int, list[dict]]:
    result: dict[int, list[dict]] = {}
    for action in actions:
        actionid = as_int(action.get("actionid"))
        if actionid is None:
            continue
        try:
            alerts = await client.recent_alerts_for_action(actionid, limit=limit, time_from=time_from)
            result[actionid] = summarize_action_runs(alerts, max_runs=3)
        except Exception:
            # alert.get can be restricted by role. Do not invalidate the main snapshot.
            result[actionid] = []
    return result


async def collect_baseline(baseline_id: UUID) -> None:
    settings = get_settings()
    pool = await get_pool()
    client = ZabbixClient(old_endpoint())
    try:
        version = await client.version()
        async with pool.acquire() as conn:
            await conn.execute(
                "UPDATE baselines SET status='COLLECTING',started_at=now(),source_version=$2,error=NULL WHERE id=$1",
                baseline_id, version,
            )

        hosts = await client.active_hosts()
        async with pool.acquire() as conn:
            async with conn.transaction():
                proxy_map = await insert_baseline_hosts(conn, baseline_id, hosts)

        hostids = [
            value for host in hosts
            if (value := as_int(host.get("hostid"))) is not None
        ]
        sem = asyncio.Semaphore(settings.parallel_batches)
        processed = 0
        progress_lock = asyncio.Lock()

        async def process_batch(batch: list[int]) -> None:
            nonlocal processed
            async with sem:
                data = await client.host_batch(batch)
                async with pool.acquire() as conn:
                    async with conn.transaction():
                        await insert_baseline_batch(conn, baseline_id, data, proxy_map)
                async with progress_lock:
                    processed += len(batch)
                    async with pool.acquire() as conn:
                        await conn.execute(
                            """
                            UPDATE baselines
                            SET totals=jsonb_set(COALESCE(totals,'{}'::jsonb),'{hosts_processed}',to_jsonb($2::int),true)
                            WHERE id=$1
                            """,
                            baseline_id, processed,
                        )

        await asyncio.gather(
            *(process_batch(batch) for batch in chunks(hostids, settings.hosts_per_batch))
        )

        proxies, actions, media_types, drules = await asyncio.gather(
            client.proxies(), client.actions(), client.media_types(), client.network_discovery_rules()
        )
        action_runs = await collect_action_runs(
            client, actions, settings.action_alert_scan_limit
        )

        async with pool.acquire() as conn:
            async with conn.transaction():
                await insert_baseline_globals(
                    conn, baseline_id, proxies, actions, media_types, action_runs, drules
                )
                await rebuild_baseline_lld_stats(conn, baseline_id)
                totals = {
                    "hosts": await conn.fetchval(
                        "SELECT count(*) FROM baseline_hosts WHERE baseline_id=$1", baseline_id
                    ),
                    "interfaces": await conn.fetchval(
                        "SELECT count(*) FROM baseline_interfaces WHERE baseline_id=$1 AND eligible", baseline_id
                    ),
                    "items": await conn.fetchval(
                        "SELECT count(*) FROM baseline_items WHERE baseline_id=$1 AND eligible", baseline_id
                    ),
                    "triggers": await conn.fetchval(
                        "SELECT count(*) FROM baseline_triggers WHERE baseline_id=$1 AND eligible", baseline_id
                    ),
                    "llds": await conn.fetchval(
                        "SELECT count(*) FROM baseline_llds WHERE baseline_id=$1 AND eligible", baseline_id
                    ),
                    "proxies": await conn.fetchval(
                        "SELECT count(*) FROM baseline_proxies WHERE baseline_id=$1", baseline_id
                    ),
                    "actions": await conn.fetchval(
                        "SELECT count(*) FROM baseline_actions WHERE baseline_id=$1 AND eligible", baseline_id
                    ),
                    "media_types": await conn.fetchval(
                        "SELECT count(*) FROM baseline_media_types WHERE baseline_id=$1 AND eligible", baseline_id
                    ),
                    "network_discoveries": await conn.fetchval(
                        "SELECT count(*) FROM baseline_drules WHERE baseline_id=$1 AND eligible", baseline_id
                    ),
                }
                await conn.execute(
                    "UPDATE baselines SET status='READY',finished_at=now(),totals=$2::jsonb WHERE id=$1",
                    baseline_id, json.dumps(totals),
                )
    except Exception as exc:
        async with pool.acquire() as conn:
            await conn.execute(
                "UPDATE baselines SET status='FAILED',finished_at=now(),error=$2 WHERE id=$1",
                baseline_id, str(exc),
            )
        raise
    finally:
        await client.close()


async def collect_current_cycle(baseline_id: UUID) -> UUID:
    settings = get_settings()
    pool = await get_pool()
    client = ZabbixClient(new_endpoint())

    async with pool.acquire() as conn:
        active_slot = await conn.fetchval(
            "SELECT COALESCE((SELECT (value #>> '{}')::int FROM app_meta WHERE key='active_slot'),0)"
        )
        slot = 1 - int(active_slot or 0)
        cycle_id = await conn.fetchval(
            "INSERT INTO cycles(baseline_id,slot,status) VALUES($1,$2,'RUNNING') RETURNING id",
            baseline_id, slot,
        )
        await clear_slot(conn, slot)
        frozen_at = await conn.fetchval("SELECT frozen_at FROM baselines WHERE id=$1", baseline_id)
        action_time_from = int(frozen_at.timestamp()) if frozen_at else None
        hostids = [
            row["hostid"]
            for row in await conn.fetch(
                "SELECT hostid FROM baseline_hosts WHERE baseline_id=$1 ORDER BY hostid", baseline_id
            )
        ]
        await conn.execute(
            "UPDATE cycles SET hosts_total=$2 WHERE id=$1", cycle_id, len(hostids)
        )

    try:
        await client.version()
        sem = asyncio.Semaphore(settings.parallel_batches)
        progress_lock = asyncio.Lock()
        processed = 0

        async def process_batch(batch: list[int]) -> None:
            nonlocal processed
            async with sem:
                current_hosts = await client.hosts_by_ids(batch)
                async with pool.acquire() as conn:
                    async with conn.transaction():
                        proxy_map = await insert_state_hosts(conn, slot, current_hosts)

                data = await client.host_batch(batch)
                async with pool.acquire() as conn:
                    async with conn.transaction():
                        await insert_state_batch(conn, slot, data, proxy_map)

                async with progress_lock:
                    processed += len(batch)
                    async with pool.acquire() as conn:
                        await conn.execute(
                            "UPDATE cycles SET hosts_processed=$2 WHERE id=$1", cycle_id, processed
                        )

        await asyncio.gather(
            *(process_batch(batch) for batch in chunks(hostids, settings.hosts_per_batch))
        )

        proxies, actions, media_types, drules = await asyncio.gather(
            client.proxies(), client.actions(), client.media_types(), client.network_discovery_rules()
        )
        action_runs = await collect_action_runs(
            client, actions, settings.action_alert_scan_limit, time_from=action_time_from
        )

        async with pool.acquire() as conn:
            async with conn.transaction():
                await insert_state_globals(
                    conn, slot, proxies, actions, media_types, action_runs, drules
                )
                await rebuild_state_lld_stats(conn, slot)
                metrics = await compute_metrics(conn, baseline_id, slot)
                await build_change_events(conn, cycle_id, baseline_id, slot)
                await conn.execute(
                    "UPDATE cycles SET status='COMPLETE',finished_at=now(),metrics=$2::jsonb WHERE id=$1",
                    cycle_id, json.dumps(metrics),
                )
                await conn.execute(
                    """
                    INSERT INTO app_meta(key,value) VALUES('active_slot',to_jsonb($1::int))
                    ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value,updated_at=now()
                    """,
                    slot,
                )
                await conn.execute(
                    """
                    INSERT INTO app_meta(key,value) VALUES('last_complete_cycle',to_jsonb($1::text))
                    ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value,updated_at=now()
                    """,
                    str(cycle_id),
                )
        return cycle_id
    except Exception as exc:
        async with pool.acquire() as conn:
            await conn.execute(
                "UPDATE cycles SET status='FAILED',finished_at=now(),error=$2 WHERE id=$1",
                cycle_id, str(exc),
            )
        raise
    finally:
        await client.close()
