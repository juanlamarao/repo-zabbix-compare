from __future__ import annotations

import json
from uuid import UUID
import asyncpg


async def compute_metrics(conn: asyncpg.Connection, baseline_id: UUID, slot: int) -> dict:
    metrics: dict[str, int | float] = {}

    metrics["hosts_total"] = await conn.fetchval(
        "SELECT count(*) FROM baseline_hosts WHERE baseline_id=$1", baseline_id
    )
    metrics["hosts_ok"] = await conn.fetchval(
        """
        SELECT count(*)
        FROM baseline_hosts b
        JOIN state_hosts s ON s.slot=$2 AND s.hostid=b.hostid
        WHERE b.baseline_id=$1 AND s.status=0
        """,
        baseline_id, slot,
    )
    metrics["hosts_regression"] = metrics["hosts_total"] - metrics["hosts_ok"]

    metrics["interfaces_total"] = await conn.fetchval(
        "SELECT count(*) FROM baseline_interfaces WHERE baseline_id=$1 AND eligible", baseline_id
    )
    metrics["interfaces_ok"] = await conn.fetchval(
        """
        SELECT count(*)
        FROM baseline_interfaces b
        JOIN state_interfaces s ON s.slot=$2 AND s.interfaceid=b.interfaceid
        WHERE b.baseline_id=$1 AND b.eligible
          AND COALESCE(s.available,0)<>2 AND COALESCE(s.error,'')=''
        """,
        baseline_id, slot,
    )
    metrics["interfaces_regression"] = metrics["interfaces_total"] - metrics["interfaces_ok"]

    metrics["items_total"] = await conn.fetchval(
        "SELECT count(*) FROM baseline_items WHERE baseline_id=$1 AND eligible", baseline_id
    )
    metrics["items_ok"] = await conn.fetchval(
        """
        SELECT count(*)
        FROM baseline_items b
        JOIN state_items s ON s.slot=$2 AND s.itemid=b.itemid
        WHERE b.baseline_id=$1 AND b.eligible
          AND s.status=0 AND s.state=0 AND COALESCE(s.error,'')=''
          AND COALESCE(s.discovery_status,0)=0 AND COALESCE(s.ts_delete,0)=0
          AND s.lastclock>COALESCE(b.lastclock,0)
        """,
        baseline_id, slot,
    )
    metrics["items_pending"] = await conn.fetchval(
        """
        SELECT count(*)
        FROM baseline_items b
        JOIN state_items s ON s.slot=$2 AND s.itemid=b.itemid
        WHERE b.baseline_id=$1 AND b.eligible
          AND s.status=0 AND s.state=0 AND COALESCE(s.error,'')=''
          AND COALESCE(s.discovery_status,0)=0 AND COALESCE(s.ts_delete,0)=0
          AND s.lastclock<=COALESCE(b.lastclock,0)
        """,
        baseline_id, slot,
    )
    metrics["items_unsupported"] = await conn.fetchval(
        """
        SELECT count(*)
        FROM baseline_items b
        JOIN state_items s ON s.slot=$2 AND s.itemid=b.itemid
        WHERE b.baseline_id=$1 AND b.eligible
          AND (s.state<>0 OR COALESCE(s.error,'')<>'')
        """,
        baseline_id, slot,
    )
    metrics["items_lld_lost"] = await conn.fetchval(
        """
        SELECT count(*)
        FROM baseline_items b
        JOIN state_items s ON s.slot=$2 AND s.itemid=b.itemid
        WHERE b.baseline_id=$1 AND b.eligible
          AND (COALESCE(s.discovery_status,0)=1 OR COALESCE(s.ts_delete,0)>0)
        """,
        baseline_id, slot,
    )
    metrics["items_missing"] = await conn.fetchval(
        """
        SELECT count(*)
        FROM baseline_items b
        LEFT JOIN state_items s ON s.slot=$2 AND s.itemid=b.itemid
        WHERE b.baseline_id=$1 AND b.eligible AND s.itemid IS NULL
        """,
        baseline_id, slot,
    )
    metrics["items_percent"] = (
        round(metrics["items_ok"] * 100 / metrics["items_total"], 3)
        if metrics["items_total"] else 100.0
    )

    metrics["triggers_total"] = await conn.fetchval(
        "SELECT count(*) FROM baseline_triggers WHERE baseline_id=$1 AND eligible", baseline_id
    )
    metrics["triggers_ok"] = await conn.fetchval(
        """
        SELECT count(*)
        FROM baseline_triggers b
        JOIN state_triggers s ON s.slot=$2 AND s.triggerid=b.triggerid
        WHERE b.baseline_id=$1 AND b.eligible
          AND s.status=0 AND s.state=0 AND COALESCE(s.error,'')=''
          AND COALESCE(s.discovery_status,0)=0 AND COALESCE(s.ts_delete,0)=0
        """,
        baseline_id, slot,
    )
    metrics["triggers_regression"] = metrics["triggers_total"] - metrics["triggers_ok"]
    metrics["trigger_value_changed"] = await conn.fetchval(
        """
        SELECT count(*)
        FROM baseline_triggers b
        JOIN state_triggers s ON s.slot=$2 AND s.triggerid=b.triggerid
        WHERE b.baseline_id=$1 AND b.eligible AND s.value IS DISTINCT FROM b.value
        """,
        baseline_id, slot,
    )

    metrics["lld_total"] = await conn.fetchval(
        "SELECT count(*) FROM baseline_llds WHERE baseline_id=$1 AND eligible", baseline_id
    )
    metrics["lld_ok"] = await conn.fetchval(
        """
        SELECT count(*)
        FROM baseline_llds b
        JOIN state_llds s ON s.slot=$2 AND s.itemid=b.itemid
        WHERE b.baseline_id=$1 AND b.eligible
          AND s.status=0 AND s.state=0 AND COALESCE(s.error,'')=''
        """,
        baseline_id, slot,
    )
    metrics["lld_regression"] = metrics["lld_total"] - metrics["lld_ok"]
    metrics["lld_mass_loss"] = await conn.fetchval(
        """
        SELECT count(DISTINCT b.lldid)
        FROM baseline_lld_child_stats b
        LEFT JOIN state_lld_child_stats s
          ON s.slot=$2 AND s.lldid=b.lldid
         AND s.object_kind=b.object_kind AND s.prototype_id=b.prototype_id
        WHERE b.baseline_id=$1 AND b.eligible_children>0
          AND COALESCE(s.discovered_children,0)=0
        """,
        baseline_id, slot,
    )
    metrics["lld_lost_children"] = await conn.fetchval(
        """
        SELECT COALESCE(sum(s.lost_children),0)
        FROM state_lld_child_stats s
        JOIN baseline_lld_child_stats b
          ON b.baseline_id=$1 AND b.lldid=s.lldid
         AND b.object_kind=s.object_kind AND b.prototype_id=s.prototype_id
        WHERE s.slot=$2 AND b.eligible_children>0
        """,
        baseline_id, slot,
    )
    metrics["lld_scheduled_delete"] = await conn.fetchval(
        """
        SELECT COALESCE(sum(s.scheduled_delete),0)
        FROM state_lld_child_stats s
        JOIN baseline_lld_child_stats b
          ON b.baseline_id=$1 AND b.lldid=s.lldid
         AND b.object_kind=s.object_kind AND b.prototype_id=s.prototype_id
        WHERE s.slot=$2 AND b.eligible_children>0
        """,
        baseline_id, slot,
    )
    metrics["lld_scheduled_disable"] = await conn.fetchval(
        """
        SELECT COALESCE(sum(s.scheduled_disable),0)
        FROM state_lld_child_stats s
        JOIN baseline_lld_child_stats b
          ON b.baseline_id=$1 AND b.lldid=s.lldid
         AND b.object_kind=s.object_kind AND b.prototype_id=s.prototype_id
        WHERE s.slot=$2 AND b.eligible_children>0
        """,
        baseline_id, slot,
    )

    metrics["lld_retention_regression"] = await conn.fetchval(
        """
        SELECT count(*)
        FROM baseline_llds b
        JOIN state_llds s ON s.slot=$2 AND s.itemid=b.itemid
        WHERE b.baseline_id=$1 AND b.eligible
          AND COALESCE(b.lifetime,'')<>'0'
          AND (COALESCE(s.lifetime_type,0)=2 OR (COALESCE(s.lifetime_type,0)=0 AND COALESCE(s.lifetime,'')='0'))
        """,
        baseline_id, slot,
    )

    metrics["network_discoveries_total"] = await conn.fetchval(
        "SELECT count(*) FROM baseline_drules WHERE baseline_id=$1 AND eligible", baseline_id
    )
    metrics["network_discoveries_ok"] = await conn.fetchval(
        """
        SELECT count(*) FROM baseline_drules b
        JOIN state_drules s ON s.slot=$2 AND s.druleid=b.druleid
        WHERE b.baseline_id=$1 AND b.eligible AND s.status=0
        """,
        baseline_id, slot,
    )
    metrics["network_discoveries_regression"] = (
        metrics["network_discoveries_total"] - metrics["network_discoveries_ok"]
    )

    metrics["proxies_total"] = await conn.fetchval(
        "SELECT count(*) FROM baseline_proxies WHERE baseline_id=$1", baseline_id
    )
    metrics["proxies_present"] = await conn.fetchval(
        """
        SELECT count(*) FROM baseline_proxies b
        JOIN state_proxies s ON s.slot=$2 AND s.proxyid=b.proxyid
        WHERE b.baseline_id=$1
        """,
        baseline_id, slot,
    )

    metrics["actions_total"] = await conn.fetchval(
        "SELECT count(*) FROM baseline_actions WHERE baseline_id=$1 AND eligible", baseline_id
    )
    metrics["actions_enabled"] = await conn.fetchval(
        """
        SELECT count(*) FROM baseline_actions b
        JOIN state_actions s ON s.slot=$2 AND s.actionid=b.actionid
        WHERE b.baseline_id=$1 AND b.eligible AND s.status=0
        """,
        baseline_id, slot,
    )
    metrics["actions_expected_disabled"] = await conn.fetchval(
        """
        SELECT count(*) FROM baseline_actions b
        JOIN state_actions s ON s.slot=$2 AND s.actionid=b.actionid
        JOIN expected_changes e
          ON e.enabled AND e.object_type='action' AND e.object_id=b.actionid AND e.field='status'
        WHERE b.baseline_id=$1 AND b.eligible AND s.status<>0
        """,
        baseline_id, slot,
    )

    metrics["media_total"] = await conn.fetchval(
        "SELECT count(*) FROM baseline_media_types WHERE baseline_id=$1 AND eligible", baseline_id
    )
    metrics["media_enabled"] = await conn.fetchval(
        """
        SELECT count(*) FROM baseline_media_types b
        JOIN state_media_types s ON s.slot=$2 AND s.mediatypeid=b.mediatypeid
        WHERE b.baseline_id=$1 AND b.eligible AND s.status=0
        """,
        baseline_id, slot,
    )
    metrics["media_expected_disabled"] = await conn.fetchval(
        """
        SELECT count(*) FROM baseline_media_types b
        JOIN state_media_types s ON s.slot=$2 AND s.mediatypeid=b.mediatypeid
        JOIN expected_changes e
          ON e.enabled AND e.object_type='media_type' AND e.object_id=b.mediatypeid AND e.field='status'
        WHERE b.baseline_id=$1 AND b.eligible AND s.status<>0
        """,
        baseline_id, slot,
    )
    return metrics


async def build_change_events(
    conn: asyncpg.Connection, cycle_id: UUID, baseline_id: UUID, slot: int
) -> None:
    await conn.execute("DELETE FROM change_events WHERE cycle_id=$1", cycle_id)

    rows = await conn.fetch(
        """
        SELECT b.lldid,b.object_kind,b.prototype_id,b.eligible_children,
               COALESCE(s.existing_children,0) existing_children,
               COALESCE(s.discovered_children,0) discovered_children,
               COALESCE(s.lost_children,0) lost_children,
               COALESCE(s.scheduled_delete,0) scheduled_delete,
               COALESCE(s.scheduled_disable,0) scheduled_disable
        FROM baseline_lld_child_stats b
        LEFT JOIN state_lld_child_stats s
          ON s.slot=$2 AND s.lldid=b.lldid
         AND s.object_kind=b.object_kind AND s.prototype_id=b.prototype_id
        WHERE b.baseline_id=$1 AND b.eligible_children>0
          AND (COALESCE(s.discovered_children,0)=0 OR COALESCE(s.lost_children,0)>0)
        """,
        baseline_id, slot,
    )
    for row in rows:
        details = dict(row)
        baseline = row["eligible_children"]
        current = row["discovered_children"]
        if current == 0:
            severity = "CRITICAL"
            code = "LLD_ZERO_DISCOVERY"
            message = (
                f"LLD {row['lldid']} / prototype {row['prototype_id']} ({row['object_kind']}) "
                f"caiu de {baseline} filhos saudáveis para 0 descobertos."
            )
        else:
            loss_pct = (baseline - current) * 100 / baseline
            severity = "HIGH" if loss_pct >= 50 else "WARNING"
            code = "LLD_CHILD_LOSS"
            message = (
                f"LLD {row['lldid']} / prototype {row['prototype_id']} perdeu filhos: "
                f"baseline={baseline}, descobertos={current}, lost={row['lost_children']}."
            )
        await conn.execute(
            """
            INSERT INTO change_events(cycle_id,object_type,object_id,severity,code,message,details)
            VALUES($1,'lld',$2,$3,$4,$5,$6::jsonb)
            """,
            cycle_id, row["lldid"], severity, code, message, json.dumps(details),
        )

    retention_rows = await conn.fetch(
        """
        SELECT b.itemid,b.name,b.lifetime AS baseline_lifetime,s.lifetime AS current_lifetime,
               s.lifetime_type,s.enabled_lifetime,s.enabled_lifetime_type
        FROM baseline_llds b
        JOIN state_llds s ON s.slot=$2 AND s.itemid=b.itemid
        WHERE b.baseline_id=$1 AND b.eligible
          AND COALESCE(b.lifetime,'')<>'0'
          AND (COALESCE(s.lifetime_type,0)=2 OR (COALESCE(s.lifetime_type,0)=0 AND COALESCE(s.lifetime,'')='0'))
        """,
        baseline_id, slot,
    )
    for row in retention_rows:
        await conn.execute(
            """
            INSERT INTO change_events(cycle_id,object_type,object_id,severity,code,message,details)
            VALUES($1,'lld',$2,'CRITICAL','LLD_RETENTION_IMMEDIATE',$3,$4::jsonb)
            """,
            cycle_id, row["itemid"],
            f"LLD {row['name']} ({row['itemid']}) passou de retenção {row['baseline_lifetime']} para remoção imediata/0.",
            json.dumps(dict(row)),
        )

    counts = await conn.fetchrow(
        """
        SELECT
          count(*) FILTER(WHERE s.itemid IS NULL) AS missing,
          count(*) FILTER(WHERE s.itemid IS NOT NULL AND (s.state<>0 OR COALESCE(s.error,'')<>'')) AS unsupported,
          count(*) FILTER(WHERE s.itemid IS NOT NULL AND (COALESCE(s.discovery_status,0)=1 OR COALESCE(s.ts_delete,0)>0)) AS lost
        FROM baseline_items b
        LEFT JOIN state_items s ON s.slot=$2 AND s.itemid=b.itemid
        WHERE b.baseline_id=$1 AND b.eligible
        """,
        baseline_id, slot,
    )
    for code, key, severity in (
        ("ITEM_MISSING", "missing", "HIGH"),
        ("ITEM_UNSUPPORTED", "unsupported", "HIGH"),
        ("ITEM_LLD_LOST", "lost", "CRITICAL"),
    ):
        count = counts[key]
        if count:
            await conn.execute(
                """
                INSERT INTO change_events(cycle_id,object_type,object_id,severity,code,message,details)
                VALUES($1,'item',0,$2,$3,$4,$5::jsonb)
                """,
                cycle_id, severity, code, f"{count} itens do baseline estão em {key}.",
                json.dumps({"count": count}),
            )
