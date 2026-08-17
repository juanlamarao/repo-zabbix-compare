from __future__ import annotations
from typing import Any


def as_int(value: Any, default: int | None = None) -> int | None:
    if value in (None, ""):
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def as_text(value: Any) -> str:
    return "" if value is None else str(value)


def sub_object(obj: dict[str, Any], key: str) -> dict[str, Any]:
    value = obj.get(key)
    if isinstance(value, dict):
        return value
    if isinstance(value, list) and value and isinstance(value[0], dict):
        return value[0]
    return {}


def discovery_rule_id(obj: dict[str, Any]) -> int | None:
    value = obj.get("discoveryRule")
    if isinstance(value, dict):
        return as_int(value.get("itemid"))
    if isinstance(value, list) and value and isinstance(value[0], dict):
        return as_int(value[0].get("itemid"))
    return None


def interface_eligible(obj: dict[str, Any]) -> bool:
    # available=2 means unavailable. available=0 is retained because active-check
    # interfaces can legitimately remain unknown while the item itself is healthy.
    return as_int(obj.get("available"), 0) != 2 and not as_text(obj.get("error")).strip()


def item_eligible(obj: dict[str, Any]) -> bool:
    disc = sub_object(obj, "itemDiscovery")
    is_currently_discovered = as_int(disc.get("status"), 0) == 0 and as_int(disc.get("ts_delete"), 0) == 0
    return (
        as_int(obj.get("status"), 1) == 0
        and as_int(obj.get("state"), 1) == 0
        and not as_text(obj.get("error")).strip()
        and is_currently_discovered
    )


def trigger_eligible(obj: dict[str, Any]) -> bool:
    disc = sub_object(obj, "triggerDiscovery")
    is_currently_discovered = as_int(disc.get("status"), 0) == 0 and as_int(disc.get("ts_delete"), 0) == 0
    return (
        as_int(obj.get("status"), 1) == 0
        and as_int(obj.get("state"), 1) == 0
        and not as_text(obj.get("error")).strip()
        and is_currently_discovered
    )


def lld_eligible(obj: dict[str, Any]) -> bool:
    return as_int(obj.get("status"), 1) == 0 and as_int(obj.get("state"), 1) == 0 and not as_text(obj.get("error")).strip()


def normalize_proxy(obj: dict[str, Any]) -> dict[str, Any]:
    return {
        "proxyid": as_int(obj.get("proxyid")),
        "name": as_text(obj.get("name") or obj.get("host")),
        "mode": as_text(obj.get("operating_mode") if "operating_mode" in obj else obj.get("status")),
        "lastaccess": as_int(obj.get("lastaccess")),
        "version": as_text(obj.get("version")) or None,
        "compatibility": as_int(obj.get("compatibility")),
        "state": as_int(obj.get("state")),
        "raw": obj,
    }


def summarize_action_runs(alerts: list[dict[str, Any]], max_runs: int = 3) -> list[dict[str, Any]]:
    grouped: dict[int, list[dict[str, Any]]] = {}
    order: list[int] = []
    for alert in alerts:
        eventid = as_int(alert.get("eventid"), 0) or 0
        if eventid not in grouped:
            grouped[eventid] = []
            order.append(eventid)
        grouped[eventid].append(alert)

    result: list[dict[str, Any]] = []
    for eventid in order[:max_runs]:
        rows = grouped[eventid]
        statuses = {as_int(row.get("status"), -1) for row in rows}
        errors = [as_text(row.get("error")).strip() for row in rows if as_text(row.get("error")).strip()]
        # Alert status: 0 not sent, 1 sent, 2 failed, 3 new in some versions.
        if errors or any(status not in (0, 1) for status in statuses):
            summary = "FAILED"
        elif statuses == {1}:
            summary = "SENT"
        elif 1 in statuses and 0 in statuses:
            summary = "PARTIAL"
        else:
            summary = "PENDING"
        result.append(
            {
                "eventid": eventid,
                "clock": max(as_int(row.get("clock"), 0) or 0 for row in rows),
                "summary_status": summary,
                "alerts": rows,
            }
        )
    return result
