import sqlite3
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from zbx_migration_checker.compare import compare_snapshot_to_current
from zbx_migration_checker.config import ReportConfig
from zbx_migration_checker.snapshot import ITEM_COLUMNS, create_snapshot_schema
from zbx_migration_checker.web import api_interface_hosts, api_items


class FakeDB:
    def __init__(self):
        self.cfg = SimpleNamespace(host="z7", database="zabbix")
        self.items = {
            100: self._item(100, 1, 0, 3, "icmpping", rt_state=1, rt_error="", interface_error="HTTP expected 422"),
            101: self._item(101, 2, 1, 0, "agent.ping", rt_state=1, rt_error="agent down"),
            102: self._item(102, 1, 0, 0, "agent.version", rt_state=0, rt_error=""),
        }
        self.hosts = {
            1: {"hostid": 1, "host": "host-a", "host_name": "Host A", "host_status": 0, "proxy_ref": None},
            2: {"hostid": 2, "host": "host-b", "host_name": "Host B", "host_status": 1, "proxy_ref": None},
        }

    @staticmethod
    def _item(itemid, hostid, host_status, item_type, key, rt_state, rt_error, interface_error=""):
        d = {c: None for c in ITEM_COLUMNS}
        d.update({
            "itemid": itemid, "hostid": hostid, "item_status": 0, "flags": 0,
            "item_type": item_type, "value_type": 3, "key_": key, "name": key,
            "delay": "1m", "interfaceid": 10 if hostid == 1 else 20, "master_itemid": 0,
            "snmp_oid": "", "timeout": "3s", "templateid": 0,
            "host": "host-a" if hostid == 1 else "host-b", "host_name": "Host A" if hostid == 1 else "Host B",
            "host_status": host_status, "proxy_ref": None, "rt_state": rt_state, "rt_error": rt_error,
            "interface_type": 1, "interface_available": 1, "interface_error": interface_error,
            "interface_ip": "127.0.0.1", "interface_dns": "", "interface_port": "10050",
        })
        return d

    def validate_required_schema(self): return []
    def db_version(self): return {"mandatory": 7000000, "optional": 7000000}
    def fetch_items(self, ids): return [dict(self.items[i]) for i in ids if i in self.items]
    def fetch_item_presence(self, ids): return {i: self.items[i] for i in ids if i in self.items}
    def fetch_discovery(self, ids): return []
    def fetch_hosts(self, ids): return [dict(self.hosts[i]) for i in ids if i in self.hosts]
    def fetch_host_interfaces(self, ids):
        rows = []
        if 1 in ids:
            # One failing + one healthy interface: host 1 must remain in the normal analysis.
            rows.extend([
                {"interfaceid": 10, "hostid": 1, "interface_type": 1, "interface_main": 1, "interface_useip": 1, "interface_ip": "127.0.0.1", "interface_dns": "", "interface_port": "10050", "interface_available": 2, "interface_error": "HTTP expected 422"},
                {"interfaceid": 11, "hostid": 1, "interface_type": 2, "interface_main": 1, "interface_useip": 1, "interface_ip": "127.0.0.2", "interface_dns": "", "interface_port": "161", "interface_available": 1, "interface_error": ""},
            ])
        if 2 in ids:
            rows.append({"interfaceid": 20, "hostid": 2, "interface_type": 1, "interface_main": 1, "interface_useip": 1, "interface_ip": "127.0.0.3", "interface_dns": "", "interface_port": "10050", "interface_available": 2, "interface_error": "agent down"})
        return rows


class FakeDBAllInterfacesFail(FakeDB):
    def fetch_host_interfaces(self, ids):
        rows = super().fetch_host_interfaces(ids)
        # Remove the only healthy interface from host 1. Host 2 is disabled and must not enter the failure screen.
        return [r for r in rows if r["interfaceid"] != 11]


class CompareV04Tests(unittest.TestCase):
    def _baseline(self, path: Path):
        conn = sqlite3.connect(path)
        create_snapshot_schema(conn)
        conn.execute("INSERT INTO metadata(key,value) VALUES ('zabbix_dbversion','{}')")
        q = f"INSERT INTO items({','.join(ITEM_COLUMNS)}) VALUES ({','.join('?' for _ in ITEM_COLUMNS)})"
        rows = []
        for itemid, hostid, item_type, key in [
            (100, 1, 3, "icmpping"),
            (101, 2, 0, "agent.ping"),
            (102, 1, 0, "agent.version"),
            (103, 1, 0, "missing.real"),
            (104, 2, 0, "missing.but.host.disabled"),
        ]:
            d = {c: None for c in ITEM_COLUMNS}
            d.update({
                "itemid": itemid, "hostid": hostid, "item_status": 0, "flags": 0,
                "item_type": item_type, "value_type": 3, "key_": key, "name": key,
                "delay": "1m", "interfaceid": 10 if hostid == 1 else 20, "master_itemid": 0,
                "snmp_oid": "", "timeout": "3s", "templateid": 0,
                "host": "host-a" if hostid == 1 else "host-b", "host_name": "Host A" if hostid == 1 else "Host B",
                "host_status": 0, "proxy_ref": None, "rt_state": 0, "rt_error": "",
                "interface_type": 1, "interface_available": 1, "interface_error": "",
                "interface_ip": "127.0.0.1", "interface_dns": "", "interface_port": "10050",
            })
            rows.append(tuple(d[c] for c in ITEM_COLUMNS))
        conn.executemany(q, rows)
        conn.commit(); conn.close()

    def test_disabled_hosts_ignored_and_errors_not_crossed(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td) / "base.sqlite"
            out = Path(td) / "out"
            self._baseline(base)
            result, summary = compare_snapshot_to_current(base, FakeDB(), out, ReportConfig(batch_size=100), force=True)
            conn = sqlite3.connect(result)
            conn.row_factory = sqlite3.Row
            ids = {r[0] for r in conn.execute("SELECT itemid FROM anomalies")}
            self.assertEqual(ids, {100, 103})  # 104 is absent, but its host is disabled in Zabbix 7
            row = conn.execute("SELECT category,current_error,current_interface_error,baseline_item_type,current_item_type,current_key_ FROM anomalies WHERE itemid=100").fetchone()
            self.assertEqual(row[0], "ITEM_NOT_SUPPORTED")
            self.assertIn(row[1], (None, ""))
            self.assertEqual(row[2], "HTTP expected 422")
            self.assertEqual((row[3], row[4], row[5]), (3, 3, "icmpping"))
            missing = conn.execute("SELECT category FROM anomalies WHERE itemid=103").fetchone()[0]
            self.assertEqual(missing, "ITEM_MISSING")
            ignored = conn.execute("SELECT value FROM metadata WHERE key='ignored_current_disabled_hosts'").fetchone()[0]
            self.assertEqual(ignored, "1")
            conn.close()

            # Server-side column filter and sort.
            page = api_items(result, {"f_itemid": ["100"], "sort": ["itemid"], "dir": ["asc"], "page": ["1"], "page_size": ["50"]})
            self.assertEqual(page["total"], 1)
            self.assertEqual(page["rows"][0]["itemid"], 100)

    def test_all_interfaces_failed_host_is_isolated_from_regressions(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td) / "base.sqlite"
            out = Path(td) / "out"
            self._baseline(base)
            result, summary = compare_snapshot_to_current(base, FakeDBAllInterfacesFail(), out, ReportConfig(batch_size=100), force=True)
            conn = sqlite3.connect(result)
            conn.row_factory = sqlite3.Row
            # Host 1 is enabled but every interface is failing; host 2 is disabled. Nothing should remain as an item regression.
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM anomalies").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM host_interface_failures").fetchone()[0], 1)
            host = conn.execute("SELECT hostid,interface_count,failing_interface_count,errors_summary FROM host_interface_failures").fetchone()
            self.assertEqual((host[0], host[1], host[2]), (1, 1, 1))
            self.assertIn("HTTP expected 422", host[3])
            self.assertEqual(summary["hosts_all_interfaces_failed"], 1)
            conn.close()

            page = api_interface_hosts(result, {"sort": ["host_name"], "dir": ["asc"], "page": ["1"], "page_size": ["50"]})
            self.assertEqual(page["host_total"], 1)
            self.assertEqual(page["total"], 1)
            self.assertEqual(page["rows"][0]["interface_error"], "HTTP expected 422")


if __name__ == "__main__":
    unittest.main()
