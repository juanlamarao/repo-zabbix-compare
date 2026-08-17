import unittest

from zbx_migration_checker.logic import (
    LossThresholds,
    classify_item,
    classify_lld_child_presence,
    loss_severity,
    structural_diff,
)


class LogicTests(unittest.TestCase):
    def test_item_ok(self):
        baseline = {"host_status": 0, "item_status": 0, "rt_state": 0}
        current = {"host_status": 0, "item_status": 0, "rt_state": 0}
        self.assertEqual(classify_item(baseline, current), ("OK", "OK"))

    def test_item_not_supported(self):
        baseline = {"host_status": 0, "item_status": 0, "rt_state": 0}
        current = {"host_status": 0, "item_status": 0, "rt_state": 1}
        self.assertEqual(classify_item(baseline, current), ("ITEM_NOT_SUPPORTED", "HIGH"))

    def test_item_missing(self):
        baseline = {"host_status": 0, "item_status": 0, "rt_state": 0}
        self.assertEqual(classify_item(baseline, None, True), ("ITEM_MISSING", "HIGH"))

    def test_host_missing(self):
        baseline = {"host_status": 0, "item_status": 0, "rt_state": 0}
        self.assertEqual(classify_item(baseline, None, False), ("HOST_MISSING", "CRITICAL"))

    def test_pending_delete_is_lost(self):
        item = {"item_status": 0}
        discovery = {"discovery_status": 0, "ts_delete": 123, "ts_disable": 0}
        self.assertEqual(classify_lld_child_presence(item, discovery), ("PENDING_DELETE", False, False))

    def test_new_lld_status_not_discovered(self):
        item = {"item_status": 0}
        discovery = {"discovery_status": 1, "ts_delete": 0, "ts_disable": 0}
        self.assertEqual(classify_lld_child_presence(item, discovery), ("NOT_DISCOVERED", False, False))

    def test_total_loss_always_critical(self):
        sev, pct, lost = loss_severity(2, 0, LossThresholds(min_absolute=10))
        self.assertEqual(sev, "CRITICAL")
        self.assertEqual(pct, 100.0)
        self.assertEqual(lost, 2)

    def test_small_non_total_loss_ignored(self):
        sev, pct, lost = loss_severity(20, 15, LossThresholds(warning_pct=20, high_pct=50, min_absolute=10))
        self.assertEqual(sev, "OK")
        self.assertEqual(lost, 5)

    def test_structural_diff(self):
        baseline = {"item_type": 3, "key_": "a", "value_type": 3, "interfaceid": 1, "master_itemid": 0, "delay": "1m", "timeout": "3s", "snmp_oid": "x"}
        current = dict(baseline)
        current["timeout"] = "5s"
        self.assertEqual(structural_diff(baseline, current), ["timeout"])


if __name__ == "__main__":
    unittest.main()
