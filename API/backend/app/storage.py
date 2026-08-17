from __future__ import annotations

import json
from typing import Any
from uuid import UUID
import asyncpg

from .normalizers import (
    as_int,
    as_text,
    sub_object,
    discovery_rule_id,
    interface_eligible,
    item_eligible,
    trigger_eligible,
    lld_eligible,
    normalize_proxy,
)


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False)


async def insert_baseline_hosts(
    conn: asyncpg.Connection, baseline_id: UUID, hosts: list[dict[str, Any]]
) -> dict[int, int | None]:
    rows: list[tuple] = []
    proxy_map: dict[int, int | None] = {}
    for host in hosts:
        hostid = as_int(host.get("hostid"))
        if hostid is None:
            continue
        proxyid = as_int(host.get("proxyid"), 0)
        proxyid = None if proxyid == 0 else proxyid
        proxy_map[hostid] = proxyid
        rows.append(
            (
                baseline_id,
                hostid,
                as_text(host.get("host")),
                as_text(host.get("name")),
                proxyid,
                as_int(host.get("status"), 0),
                as_int(host.get("maintenance_status"), 0),
                True,
            )
        )
    if rows:
        await conn.copy_records_to_table(
            "baseline_hosts",
            records=rows,
            columns=[
                "baseline_id", "hostid", "host", "name", "proxyid", "status",
                "maintenance_status", "eligible",
            ],
        )
    return proxy_map


async def insert_baseline_batch(
    conn: asyncpg.Connection,
    baseline_id: UUID,
    data: dict[str, list[dict[str, Any]]],
    proxy_map: dict[int, int | None],
) -> None:
    interface_rows = []
    for obj in data["interfaces"]:
        interface_rows.append(
            (
                baseline_id,
                as_int(obj.get("interfaceid")),
                as_int(obj.get("hostid")),
                as_int(obj.get("type"), 0),
                as_int(obj.get("main"), 0),
                as_int(obj.get("useip"), 0),
                as_text(obj.get("ip")),
                as_text(obj.get("dns")),
                as_text(obj.get("port")),
                as_int(obj.get("available"), 0),
                as_text(obj.get("error")),
                as_int(obj.get("errors_from"), 0),
                as_int(obj.get("disable_until"), 0),
                interface_eligible(obj),
            )
        )
    if interface_rows:
        await conn.copy_records_to_table(
            "baseline_interfaces",
            records=interface_rows,
            columns=[
                "baseline_id", "interfaceid", "hostid", "type", "main", "useip", "ip", "dns",
                "port", "available", "error", "errors_from", "disable_until", "eligible",
            ],
        )

    item_rows = []
    for obj in data["items"]:
        disc = sub_object(obj, "itemDiscovery")
        hostid = as_int(obj.get("hostid"))
        item_rows.append(
            (
                baseline_id,
                as_int(obj.get("itemid")),
                hostid,
                proxy_map.get(hostid or -1),
                as_int(obj.get("interfaceid"), 0) or None,
                as_text(obj.get("name")),
                as_text(obj.get("key_")),
                as_int(obj.get("type")),
                as_int(obj.get("status")),
                as_int(obj.get("state")),
                as_text(obj.get("error")),
                as_int(obj.get("lastclock"), 0),
                as_text(obj.get("lastvalue")),
                as_text(obj.get("delay")),
                as_int(obj.get("flags")),
                discovery_rule_id(obj),
                as_int(disc.get("parent_itemid")),
                as_int(disc.get("status")),
                as_int(disc.get("lastcheck")),
                as_int(disc.get("ts_delete"), 0),
                as_int(disc.get("ts_disable"), 0),
                item_eligible(obj),
            )
        )
    if item_rows:
        await conn.copy_records_to_table(
            "baseline_items",
            records=item_rows,
            columns=[
                "baseline_id", "itemid", "hostid", "proxyid", "interfaceid", "name", "key_",
                "type", "status", "state", "error", "lastclock", "lastvalue", "delay", "flags",
                "discovery_ruleid", "prototype_itemid", "discovery_status", "last_discovered",
                "ts_delete", "ts_disable", "eligible",
            ],
        )

    lld_rows = []
    for obj in data["llds"]:
        lld_rows.append(
            (
                baseline_id,
                as_int(obj.get("itemid")),
                as_int(obj.get("hostid")),
                as_text(obj.get("name")),
                as_text(obj.get("key_")),
                as_int(obj.get("status")),
                as_int(obj.get("state")),
                as_text(obj.get("error")),
                as_text(obj.get("delay")),
                as_text(obj.get("lifetime")),
                as_int(obj.get("lifetime_type")),
                as_text(obj.get("enabled_lifetime")) or None,
                as_int(obj.get("enabled_lifetime_type")),
                lld_eligible(obj),
            )
        )
    if lld_rows:
        await conn.copy_records_to_table(
            "baseline_llds",
            records=lld_rows,
            columns=[
                "baseline_id", "itemid", "hostid", "name", "key_", "status", "state", "error",
                "delay", "lifetime", "lifetime_type", "enabled_lifetime", "enabled_lifetime_type",
                "eligible",
            ],
        )

    # Triggers may reference multiple hosts and can therefore be returned by more than one host batch.
    for obj in data["triggers"]:
        disc = sub_object(obj, "triggerDiscovery")
        await conn.execute(
            """
            INSERT INTO baseline_triggers(
                baseline_id,triggerid,description,status,state,value,error,lastchange,priority,flags,
                discovery_ruleid,prototype_triggerid,discovery_status,ts_delete,ts_disable,eligible
            ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
            ON CONFLICT (baseline_id,triggerid) DO UPDATE SET
                description=EXCLUDED.description,status=EXCLUDED.status,state=EXCLUDED.state,
                value=EXCLUDED.value,error=EXCLUDED.error,lastchange=EXCLUDED.lastchange,
                priority=EXCLUDED.priority,flags=EXCLUDED.flags,discovery_ruleid=EXCLUDED.discovery_ruleid,
                prototype_triggerid=EXCLUDED.prototype_triggerid,discovery_status=EXCLUDED.discovery_status,
                ts_delete=EXCLUDED.ts_delete,ts_disable=EXCLUDED.ts_disable,eligible=EXCLUDED.eligible
            """,
            baseline_id,
            as_int(obj.get("triggerid")),
            as_text(obj.get("description")),
            as_int(obj.get("status")),
            as_int(obj.get("state")),
            as_int(obj.get("value")),
            as_text(obj.get("error")),
            as_int(obj.get("lastchange"), 0),
            as_int(obj.get("priority"), 0),
            as_int(obj.get("flags")),
            discovery_rule_id(obj),
            as_int(disc.get("parent_triggerid")),
            as_int(disc.get("status")),
            as_int(disc.get("ts_delete"), 0),
            as_int(disc.get("ts_disable"), 0),
            trigger_eligible(obj),
        )


async def insert_baseline_globals(
    conn: asyncpg.Connection,
    baseline_id: UUID,
    proxies: list[dict[str, Any]],
    actions: list[dict[str, Any]],
    media_types: list[dict[str, Any]],
    action_runs: dict[int, list[dict[str, Any]]],
    drules: list[dict[str, Any]] | None = None,
) -> None:
    for proxy in proxies:
        p = normalize_proxy(proxy)
        await conn.execute(
            """
            INSERT INTO baseline_proxies(baseline_id,proxyid,name,mode,lastaccess,version,compatibility,state,raw)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb) ON CONFLICT DO NOTHING
            """,
            baseline_id, p["proxyid"], p["name"], p["mode"], p["lastaccess"], p["version"],
            p["compatibility"], p["state"], _json(p["raw"]),
        )

    for drule in drules or []:
        await conn.execute(
            """
            INSERT INTO baseline_drules(baseline_id,druleid,name,status,proxyid,delay,raw,eligible)
            VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8) ON CONFLICT DO NOTHING
            """,
            baseline_id, as_int(drule.get("druleid")), as_text(drule.get("name")),
            as_int(drule.get("status")), as_int(drule.get("proxyid"),0) or None,
            as_text(drule.get("delay")), _json(drule), as_int(drule.get("status"),1)==0,
        )

    for action in actions:
        actionid = as_int(action.get("actionid"))
        await conn.execute(
            """
            INSERT INTO baseline_actions(baseline_id,actionid,name,status,eventsource,raw,eligible)
            VALUES($1,$2,$3,$4,$5,$6::jsonb,$7) ON CONFLICT DO NOTHING
            """,
            baseline_id, actionid, as_text(action.get("name")), as_int(action.get("status")),
            as_int(action.get("eventsource")), _json(action), as_int(action.get("status"), 1) == 0,
        )
        for rank, run in enumerate(action_runs.get(actionid or -1, []), start=1):
            await conn.execute(
                """
                INSERT INTO baseline_action_runs(baseline_id,actionid,rank,eventid,clock,summary_status,alerts)
                VALUES($1,$2,$3,$4,$5,$6,$7::jsonb) ON CONFLICT DO NOTHING
                """,
                baseline_id, actionid, rank, run["eventid"], run["clock"], run["summary_status"],
                _json(run["alerts"]),
            )

    for media in media_types:
        await conn.execute(
            """
            INSERT INTO baseline_media_types(baseline_id,mediatypeid,name,type,status,raw,eligible)
            VALUES($1,$2,$3,$4,$5,$6::jsonb,$7) ON CONFLICT DO NOTHING
            """,
            baseline_id, as_int(media.get("mediatypeid")), as_text(media.get("name")),
            as_int(media.get("type")), as_int(media.get("status")), _json(media),
            as_int(media.get("status"), 1) == 0,
        )


async def clear_slot(conn: asyncpg.Connection, slot: int) -> None:
    for table in (
        "state_action_runs", "state_lld_child_stats", "state_items", "state_triggers",
        "state_interfaces", "state_llds", "state_hosts", "state_proxies", "state_actions",
        "state_media_types", "state_drules",
    ):
        await conn.execute(f"DELETE FROM {table} WHERE slot=$1", slot)


async def insert_state_hosts(
    conn: asyncpg.Connection, slot: int, hosts: list[dict[str, Any]]
) -> dict[int, int | None]:
    rows = []
    proxy_map: dict[int, int | None] = {}
    for host in hosts:
        hostid = as_int(host.get("hostid"))
        if hostid is None:
            continue
        proxyid = as_int(host.get("proxyid"), 0)
        proxyid = None if proxyid == 0 else proxyid
        proxy_map[hostid] = proxyid
        rows.append(
            (
                slot, hostid, as_text(host.get("host")), as_text(host.get("name")), proxyid,
                as_int(host.get("status")), as_int(host.get("maintenance_status")),
            )
        )
    if rows:
        await conn.copy_records_to_table(
            "state_hosts",
            records=rows,
            columns=["slot", "hostid", "host", "name", "proxyid", "status", "maintenance_status"],
        )
    return proxy_map


async def insert_state_batch(
    conn: asyncpg.Connection,
    slot: int,
    data: dict[str, list[dict[str, Any]]],
    proxy_map: dict[int, int | None],
) -> None:
    interface_rows = []
    for obj in data["interfaces"]:
        interface_rows.append(
            (
                slot, as_int(obj.get("interfaceid")), as_int(obj.get("hostid")),
                as_int(obj.get("available"), 0), as_text(obj.get("error")),
                as_int(obj.get("errors_from"), 0), as_int(obj.get("disable_until"), 0),
            )
        )
    if interface_rows:
        await conn.copy_records_to_table(
            "state_interfaces", records=interface_rows,
            columns=["slot", "interfaceid", "hostid", "available", "error", "errors_from", "disable_until"],
        )

    item_rows = []
    for obj in data["items"]:
        disc = sub_object(obj, "itemDiscovery")
        hostid = as_int(obj.get("hostid"))
        item_rows.append(
            (
                slot, as_int(obj.get("itemid")), hostid, proxy_map.get(hostid or -1),
                as_int(obj.get("status")), as_int(obj.get("state")), as_text(obj.get("error")),
                as_int(obj.get("lastclock"), 0), discovery_rule_id(obj),
                as_int(disc.get("parent_itemid")), as_int(disc.get("status")),
                as_int(disc.get("lastcheck")), as_int(disc.get("ts_delete"), 0),
                as_int(disc.get("ts_disable"), 0),
            )
        )
    if item_rows:
        await conn.copy_records_to_table(
            "state_items", records=item_rows,
            columns=[
                "slot", "itemid", "hostid", "proxyid", "status", "state", "error", "lastclock",
                "discovery_ruleid", "prototype_itemid", "discovery_status", "last_discovered",
                "ts_delete", "ts_disable",
            ],
        )

    lld_rows = []
    for obj in data["llds"]:
        lld_rows.append(
            (
                slot, as_int(obj.get("itemid")), as_int(obj.get("hostid")),
                as_int(obj.get("status")), as_int(obj.get("state")), as_text(obj.get("error")),
                as_text(obj.get("lifetime")), as_int(obj.get("lifetime_type")),
                as_text(obj.get("enabled_lifetime")) or None,
                as_int(obj.get("enabled_lifetime_type")),
            )
        )
    if lld_rows:
        await conn.copy_records_to_table(
            "state_llds", records=lld_rows,
            columns=[
                "slot", "itemid", "hostid", "status", "state", "error", "lifetime",
                "lifetime_type", "enabled_lifetime", "enabled_lifetime_type",
            ],
        )

    for obj in data["triggers"]:
        disc = sub_object(obj, "triggerDiscovery")
        await conn.execute(
            """
            INSERT INTO state_triggers(
                slot,triggerid,status,state,value,error,lastchange,discovery_ruleid,
                prototype_triggerid,discovery_status,ts_delete,ts_disable
            ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
            ON CONFLICT(slot,triggerid) DO UPDATE SET
                status=EXCLUDED.status,state=EXCLUDED.state,value=EXCLUDED.value,error=EXCLUDED.error,
                lastchange=EXCLUDED.lastchange,discovery_ruleid=EXCLUDED.discovery_ruleid,
                prototype_triggerid=EXCLUDED.prototype_triggerid,discovery_status=EXCLUDED.discovery_status,
                ts_delete=EXCLUDED.ts_delete,ts_disable=EXCLUDED.ts_disable
            """,
            slot, as_int(obj.get("triggerid")), as_int(obj.get("status")), as_int(obj.get("state")),
            as_int(obj.get("value")), as_text(obj.get("error")), as_int(obj.get("lastchange"), 0),
            discovery_rule_id(obj), as_int(disc.get("parent_triggerid")), as_int(disc.get("status")),
            as_int(disc.get("ts_delete"), 0), as_int(disc.get("ts_disable"), 0),
        )


async def insert_state_globals(
    conn: asyncpg.Connection,
    slot: int,
    proxies: list[dict[str, Any]],
    actions: list[dict[str, Any]],
    media_types: list[dict[str, Any]],
    action_runs: dict[int, list[dict[str, Any]]],
    drules: list[dict[str, Any]] | None = None,
) -> None:
    for proxy in proxies:
        p = normalize_proxy(proxy)
        await conn.execute(
            """
            INSERT INTO state_proxies(slot,proxyid,name,mode,lastaccess,version,compatibility,state,raw)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb)
            """,
            slot, p["proxyid"], p["name"], p["mode"], p["lastaccess"], p["version"],
            p["compatibility"], p["state"], _json(p["raw"]),
        )

    for drule in drules or []:
        await conn.execute(
            """
            INSERT INTO state_drules(slot,druleid,name,status,proxyid,delay,raw)
            VALUES($1,$2,$3,$4,$5,$6,$7::jsonb)
            """,
            slot, as_int(drule.get("druleid")), as_text(drule.get("name")),
            as_int(drule.get("status")), as_int(drule.get("proxyid"),0) or None,
            as_text(drule.get("delay")), _json(drule),
        )

    for action in actions:
        actionid = as_int(action.get("actionid"))
        await conn.execute(
            "INSERT INTO state_actions(slot,actionid,name,status,raw) VALUES($1,$2,$3,$4,$5::jsonb)",
            slot, actionid, as_text(action.get("name")), as_int(action.get("status")), _json(action),
        )
        for rank, run in enumerate(action_runs.get(actionid or -1, []), start=1):
            await conn.execute(
                """
                INSERT INTO state_action_runs(slot,actionid,rank,eventid,clock,summary_status,alerts)
                VALUES($1,$2,$3,$4,$5,$6,$7::jsonb)
                """,
                slot, actionid, rank, run["eventid"], run["clock"], run["summary_status"],
                _json(run["alerts"]),
            )

    for media in media_types:
        await conn.execute(
            """
            INSERT INTO state_media_types(slot,mediatypeid,name,type,status,raw)
            VALUES($1,$2,$3,$4,$5,$6::jsonb)
            """,
            slot, as_int(media.get("mediatypeid")), as_text(media.get("name")),
            as_int(media.get("type")), as_int(media.get("status")), _json(media),
        )


async def rebuild_baseline_lld_stats(conn: asyncpg.Connection, baseline_id: UUID) -> None:
    await conn.execute("DELETE FROM baseline_lld_child_stats WHERE baseline_id=$1", baseline_id)
    await conn.execute(
        """
        INSERT INTO baseline_lld_child_stats(
            baseline_id,lldid,object_kind,prototype_id,total_children,eligible_children
        )
        SELECT baseline_id,discovery_ruleid,'item',prototype_itemid,count(*),count(*) FILTER(WHERE eligible)
        FROM baseline_items
        WHERE baseline_id=$1 AND discovery_ruleid IS NOT NULL AND prototype_itemid IS NOT NULL
        GROUP BY baseline_id,discovery_ruleid,prototype_itemid
        """,
        baseline_id,
    )
    await conn.execute(
        """
        INSERT INTO baseline_lld_child_stats(
            baseline_id,lldid,object_kind,prototype_id,total_children,eligible_children
        )
        SELECT baseline_id,discovery_ruleid,'trigger',prototype_triggerid,count(*),count(*) FILTER(WHERE eligible)
        FROM baseline_triggers
        WHERE baseline_id=$1 AND discovery_ruleid IS NOT NULL AND prototype_triggerid IS NOT NULL
        GROUP BY baseline_id,discovery_ruleid,prototype_triggerid
        """,
        baseline_id,
    )


async def rebuild_state_lld_stats(conn: asyncpg.Connection, slot: int) -> None:
    await conn.execute("DELETE FROM state_lld_child_stats WHERE slot=$1", slot)
    await conn.execute(
        """
        INSERT INTO state_lld_child_stats(
            slot,lldid,object_kind,prototype_id,existing_children,discovered_children,
            lost_children,scheduled_delete,scheduled_disable
        )
        SELECT slot,discovery_ruleid,'item',prototype_itemid,count(*),
            count(*) FILTER(WHERE COALESCE(discovery_status,0)=0 AND COALESCE(ts_delete,0)=0),
            count(*) FILTER(WHERE COALESCE(discovery_status,0)=1 OR COALESCE(ts_delete,0)>0),
            count(*) FILTER(WHERE COALESCE(ts_delete,0)>0),
            count(*) FILTER(WHERE COALESCE(ts_disable,0)>0)
        FROM state_items
        WHERE slot=$1 AND discovery_ruleid IS NOT NULL AND prototype_itemid IS NOT NULL
        GROUP BY slot,discovery_ruleid,prototype_itemid
        """,
        slot,
    )
    await conn.execute(
        """
        INSERT INTO state_lld_child_stats(
            slot,lldid,object_kind,prototype_id,existing_children,discovered_children,
            lost_children,scheduled_delete,scheduled_disable
        )
        SELECT slot,discovery_ruleid,'trigger',prototype_triggerid,count(*),
            count(*) FILTER(WHERE COALESCE(discovery_status,0)=0 AND COALESCE(ts_delete,0)=0),
            count(*) FILTER(WHERE COALESCE(discovery_status,0)=1 OR COALESCE(ts_delete,0)>0),
            count(*) FILTER(WHERE COALESCE(ts_delete,0)>0),
            count(*) FILTER(WHERE COALESCE(ts_disable,0)>0)
        FROM state_triggers
        WHERE slot=$1 AND discovery_ruleid IS NOT NULL AND prototype_triggerid IS NOT NULL
        GROUP BY slot,discovery_ruleid,prototype_triggerid
        """,
        slot,
    )
