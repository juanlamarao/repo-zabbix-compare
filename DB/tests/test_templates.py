import sqlite3
import tempfile
import unittest
from pathlib import Path

from zbx_migration_checker.templates import enrich_existing_results


class TemplateGroupingTests(unittest.TestCase):
    def _baseline(self, path: Path) -> None:
        conn = sqlite3.connect(path)
        conn.executescript(
            """
            CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT);
            CREATE TABLE items(
                itemid INTEGER PRIMARY KEY,hostid INTEGER,item_status INTEGER,flags INTEGER,item_type INTEGER,
                value_type INTEGER,key_ TEXT,name TEXT,delay TEXT,interfaceid INTEGER,master_itemid INTEGER,
                snmp_oid TEXT,timeout TEXT,templateid INTEGER,host TEXT,host_name TEXT,host_status INTEGER,
                proxy_ref INTEGER,rt_state INTEGER,rt_error TEXT,interface_type INTEGER,interface_available INTEGER,
                interface_error TEXT,interface_ip TEXT,interface_dns TEXT,interface_port TEXT
            );
            CREATE TABLE discovery(itemid INTEGER PRIMARY KEY,parent_itemid INTEGER,lastcheck INTEGER,ts_delete INTEGER,discovery_status INTEGER,ts_disable INTEGER,disable_source INTEGER);
            """
        )
        cols = [
            "itemid","hostid","item_status","flags","item_type","value_type","key_","name","delay",
            "interfaceid","master_itemid","snmp_oid","timeout","templateid","host","host_name","host_status",
            "proxy_ref","rt_state","rt_error","interface_type","interface_available","interface_error",
            "interface_ip","interface_dns","interface_port",
        ]
        def r(itemid, hostid, host, templateid, status=0):
            return [itemid,hostid,0,0,0,3,f"key.{itemid}",f"item {itemid}","1m",0,0,"","3s",templateid,host,host,status,None,0,"",None,None,"","","",""]
        rows = [
            r(100,1,"srv-a",1000),
            r(101,1,"srv-a",1001),
            r(1000,50,"Template Composite",2000,3),
            r(1001,50,"Template Composite",2001,3),
            r(2000,60,"Template Base",0,3),
            r(2001,60,"Template Base",0,3),
        ]
        q = f"INSERT INTO items({','.join(cols)}) VALUES ({','.join('?' for _ in cols)})"
        conn.executemany(q, rows)
        conn.commit()
        conn.close()

    def _results(self, path: Path) -> None:
        conn = sqlite3.connect(path)
        conn.executescript(
            """
            CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT);
            CREATE TABLE anomalies(
                itemid INTEGER PRIMARY KEY,hostid INTEGER,host TEXT,host_name TEXT,item_name TEXT,key_ TEXT,
                category TEXT,severity TEXT,dependent_affected_count INTEGER,current_error TEXT
            );
            CREATE TABLE lld_rule_anomalies(
                itemid INTEGER PRIMARY KEY,hostid INTEGER,host TEXT,host_name TEXT,rule_name TEXT,key_ TEXT,
                category TEXT,severity TEXT,current_error TEXT,changed_fields TEXT
            );
            CREATE TABLE lld_summary(
                group_id INTEGER PRIMARY KEY,ruleid INTEGER,prototypeid INTEGER,hostid INTEGER,host TEXT,host_name TEXT,
                rule_name TEXT,rule_key TEXT,lost_count INTEGER,pending_delete_count INTEGER,category TEXT,severity TEXT
            );
            INSERT INTO anomalies VALUES (100,1,'srv-a','Server A','A','key.100','ITEM_NOT_SUPPORTED','HIGH',4,'err');
            INSERT INTO anomalies VALUES (101,1,'srv-a','Server A','B','key.101','ITEM_NOT_SUPPORTED','HIGH',0,'err');
            """
        )
        conn.commit()
        conn.close()

    def test_nested_inheritance_groups_by_root_template(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td) / "base.sqlite"
            results = Path(td) / "results.sqlite"
            self._baseline(base)
            self._results(results)
            out = enrich_existing_results(results, base)
            self.assertEqual(out["templates_impacted"], 1)
            conn = sqlite3.connect(results)
            row = conn.execute("SELECT template_hostid,template_name,item_regressions,dependent_affected FROM template_summary").fetchone()
            self.assertEqual(row, (60, "Template Base", 2, 4))
            mapped = conn.execute("SELECT base_template_name,template_depth FROM anomalies WHERE itemid=100").fetchone()
            self.assertEqual(mapped, ("Template Base", 2))
            conn.close()


if __name__ == "__main__":
    unittest.main()
