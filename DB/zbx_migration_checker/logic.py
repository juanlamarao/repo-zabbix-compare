from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


ITEM_FLAGS_NORMAL = 0
ITEM_FLAGS_DISCOVERY_RULE = 1
ITEM_FLAGS_PROTOTYPE = 2
ITEM_FLAGS_DISCOVERED = 4

HOST_STATUS_MONITORED = 0
ITEM_STATUS_ENABLED = 0
ITEM_STATE_NORMAL = 0


@dataclass(frozen=True)
class LossThresholds:
    warning_pct: float = 20.0
    high_pct: float = 50.0
    min_absolute: int = 10


def is_baseline_item_eligible(row: Mapping[str, Any]) -> bool:
    """True when an item was actually healthy/collecting in the baseline.

    Discovery rules and prototypes are handled by dedicated analyses.
    """
    return (
        row.get("host_status") == HOST_STATUS_MONITORED
        and row.get("item_status") == ITEM_STATUS_ENABLED
        and row.get("rt_state") == ITEM_STATE_NORMAL
        and row.get("flags") in (ITEM_FLAGS_NORMAL, ITEM_FLAGS_DISCOVERED)
    )


def is_baseline_lld_rule_eligible(row: Mapping[str, Any]) -> bool:
    return (
        row.get("host_status") == HOST_STATUS_MONITORED
        and row.get("item_status") == ITEM_STATUS_ENABLED
        and row.get("rt_state") == ITEM_STATE_NORMAL
        and row.get("flags") == ITEM_FLAGS_DISCOVERY_RULE
    )


def classify_item(
    baseline: Mapping[str, Any],
    current: Mapping[str, Any] | None,
    current_host_exists: bool | None = None,
) -> tuple[str, str]:
    """Return (category, severity) for a baseline-healthy item."""
    if current is None:
        if current_host_exists is False:
            return "HOST_MISSING", "CRITICAL"
        return "ITEM_MISSING", "HIGH"

    if current.get("host_status") is None:
        return "HOST_MISSING", "CRITICAL"
    if current.get("host_status") != HOST_STATUS_MONITORED:
        return "HOST_DISABLED", "HIGH"
    if current.get("item_status") != ITEM_STATUS_ENABLED:
        return "ITEM_DISABLED", "HIGH"
    if current.get("rt_state") is None:
        return "RTDATA_MISSING", "WARNING"
    if current.get("rt_state") != ITEM_STATE_NORMAL:
        return "ITEM_NOT_SUPPORTED", "HIGH"
    return "OK", "OK"


def classify_lld_rule(
    baseline: Mapping[str, Any],
    current: Mapping[str, Any] | None,
    current_host_exists: bool | None = None,
) -> tuple[str, str]:
    if current is None:
        if current_host_exists is False:
            return "LLD_HOST_MISSING", "CRITICAL"
        return "LLD_MISSING", "CRITICAL"
    if current.get("host_status") is None:
        return "LLD_HOST_MISSING", "CRITICAL"
    if current.get("host_status") != HOST_STATUS_MONITORED:
        return "LLD_HOST_DISABLED", "HIGH"
    if current.get("item_status") != ITEM_STATUS_ENABLED:
        return "LLD_DISABLED", "HIGH"
    if current.get("rt_state") is None:
        return "LLD_RTDATA_MISSING", "WARNING"
    if current.get("rt_state") != ITEM_STATE_NORMAL:
        return "LLD_NOT_SUPPORTED", "CRITICAL"
    return "OK", "OK"


def classify_lld_child_presence(
    current_item: Mapping[str, Any] | None,
    current_discovery: Mapping[str, Any] | None,
) -> tuple[str, bool, bool]:
    """Return (reason, present_for_discovery, operational).

    New v7 children are deliberately irrelevant; this only evaluates a child
    known by its v6 itemid.
    """
    if current_item is None:
        return "MISSING", False, False
    if current_discovery is None:
        return "DISCOVERY_METADATA_MISSING", False, False

    status = current_discovery.get("discovery_status")
    ts_delete = current_discovery.get("ts_delete") or 0
    ts_disable = current_discovery.get("ts_disable") or 0

    if status == 1:
        return "NOT_DISCOVERED", False, False
    if ts_delete > 0:
        return "PENDING_DELETE", False, False

    if current_item.get("item_status") != ITEM_STATUS_ENABLED:
        return "DISABLED", True, False
    if ts_disable > 0:
        return "PENDING_DISABLE", True, False

    return "PRESENT", True, True


def loss_severity(
    baseline_count: int,
    current_count: int,
    thresholds: LossThresholds,
) -> tuple[str, float, int]:
    if baseline_count <= 0:
        return "OK", 0.0, 0

    lost = max(0, baseline_count - current_count)
    pct = (lost / baseline_count) * 100.0

    if lost == 0:
        return "OK", pct, lost
    if current_count == 0:
        return "CRITICAL", pct, lost
    if lost < thresholds.min_absolute:
        return "OK", pct, lost
    if pct >= thresholds.high_pct:
        return "HIGH", pct, lost
    if pct >= thresholds.warning_pct:
        return "WARNING", pct, lost
    return "OK", pct, lost


def structural_diff(baseline: Mapping[str, Any], current: Mapping[str, Any]) -> list[str]:
    fields = (
        "item_type",
        "key_",
        "value_type",
        "interfaceid",
        "master_itemid",
        "delay",
        "timeout",
        "snmp_oid",
    )
    changed: list[str] = []
    for field in fields:
        if baseline.get(field) != current.get(field):
            changed.append(field)
    return changed
