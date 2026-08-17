from __future__ import annotations

import csv
import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from . import __version__
from .config import ReportConfig
from .db import MySQLDatabase, chunks
from .logic import classify_item, classify_lld_rule, loss_severity, structural_diff
from .snapshot import DISCOVERY_COLUMNS, ITEM_COLUMNS, open_sqlite, read_metadata
from .templates import enrich_template_groups

LOG = logging.getLogger(__name__)

SEVERITY_RANK = {"OK": 0, "WARNING": 1, "HIGH": 2, "CRITICAL": 3}


ANOMALY_COLUMNS = [
    "itemid", "hostid", "host", "host_name", "item_name", "key_", "category", "severity",
    "baseline_rt_state", "current_rt_state", "current_error", "baseline_item_status",
    "current_item_status", "baseline_interface_available", "current_interface_available",
    "current_interface_error", "baseline_proxy_ref", "current_proxy_ref", "master_itemid",
    "master_anomaly_itemid", "master_anomaly_category", "dependent_affected_count", "changed_fields",
]

LLD_RULE_COLUMNS = [
    "itemid", "hostid", "host", "host_name", "rule_name", "key_", "category", "severity",
    "baseline_rt_state", "current_rt_state", "current_error", "baseline_item_status",
    "current_item_status", "changed_fields",
]


def _create_results_db(path: Path, baseline_path: Path, force: bool) -> sqlite3.Connection:
    if path.exists():
        if not force:
            raise FileExistsError(f"Arquivo de resultados já existe: {path}. Use --force.")
        path.unlink()

    conn = open_sqlite(path)
    conn.execute("ATTACH DATABASE ? AS baseline", (str(baseline_path.resolve()),))
    conn.executescript(
        """
        CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT);

        CREATE TABLE current_items AS SELECT * FROM baseline.items WHERE 0;
        CREATE UNIQUE INDEX idx_current_items_itemid ON current_items(itemid);
        CREATE INDEX idx_current_items_hostid ON current_items(hostid);
        CREATE INDEX idx_current_items_master ON current_items(master_itemid);

        CREATE TABLE current_discovery AS SELECT * FROM baseline.discovery WHERE 0;
        CREATE UNIQUE INDEX idx_current_discovery_itemid ON current_discovery(itemid);
        CREATE INDEX idx_current_discovery_parent ON current_discovery(parent_itemid);

        CREATE TABLE current_hosts (
            hostid INTEGER PRIMARY KEY,
            host TEXT,
            host_name TEXT,
            host_status INTEGER,
            proxy_ref INTEGER
        );

        CREATE TABLE anomalies (
            itemid INTEGER PRIMARY KEY,
            hostid INTEGER,
            host TEXT,
            host_name TEXT,
            item_name TEXT,
            key_ TEXT,
            category TEXT,
            severity TEXT,
            baseline_rt_state INTEGER,
            current_rt_state INTEGER,
            current_error TEXT,
            baseline_item_status INTEGER,
            current_item_status INTEGER,
            baseline_interface_available INTEGER,
            current_interface_available INTEGER,
            current_interface_error TEXT,
            baseline_proxy_ref INTEGER,
            current_proxy_ref INTEGER,
            master_itemid INTEGER,
            master_anomaly_itemid INTEGER,
            master_anomaly_category TEXT,
            dependent_affected_count INTEGER DEFAULT 0,
            changed_fields TEXT
        );
        CREATE INDEX idx_anomalies_host ON anomalies(hostid);
        CREATE INDEX idx_anomalies_category ON anomalies(category);
        CREATE INDEX idx_anomalies_severity ON anomalies(severity);
        CREATE INDEX idx_anomalies_master ON anomalies(master_itemid);

        CREATE TABLE lld_rule_anomalies (
            itemid INTEGER PRIMARY KEY,
            hostid INTEGER,
            host TEXT,
            host_name TEXT,
            rule_name TEXT,
            key_ TEXT,
            category TEXT,
            severity TEXT,
            baseline_rt_state INTEGER,
            current_rt_state INTEGER,
            current_error TEXT,
            baseline_item_status INTEGER,
            current_item_status INTEGER,
            changed_fields TEXT
        );
        CREATE INDEX idx_lld_rule_category ON lld_rule_anomalies(category);

        CREATE TABLE lld_baseline_map (
            itemid INTEGER PRIMARY KEY,
            prototypeid INTEGER,
            ruleid INTEGER,
            group_id INTEGER,
            baseline_item_status INTEGER
        );
        CREATE INDEX idx_lld_map_rule ON lld_baseline_map(ruleid);
        CREATE INDEX idx_lld_map_group ON lld_baseline_map(group_id);

        CREATE TABLE lld_summary (
            group_id INTEGER PRIMARY KEY,
            ruleid INTEGER,
            prototypeid INTEGER,
            hostid INTEGER,
            host TEXT,
            host_name TEXT,
            rule_name TEXT,
            rule_key TEXT,
            mapping_status TEXT,
            baseline_count INTEGER,
            current_present_count INTEGER,
            lost_count INTEGER,
            loss_pct REAL,
            baseline_operational_count INTEGER,
            current_operational_count INTEGER,
            operational_lost_count INTEGER,
            operational_loss_pct REAL,
            missing_count INTEGER,
            metadata_missing_count INTEGER,
            not_discovered_count INTEGER,
            pending_delete_count INTEGER,
            disabled_count INTEGER,
            pending_disable_count INTEGER,
            category TEXT,
            severity TEXT
        );
        CREATE INDEX idx_lld_summary_severity ON lld_summary(severity);

        CREATE TABLE lld_child_anomalies (
            itemid INTEGER PRIMARY KEY,
            prototypeid INTEGER,
            ruleid INTEGER,
            group_id INTEGER,
            hostid INTEGER,
            host TEXT,
            item_name TEXT,
            key_ TEXT,
            reason TEXT,
            current_item_status INTEGER,
            discovery_status INTEGER,
            ts_delete INTEGER,
            ts_disable INTEGER,
            disable_source INTEGER
        );
        CREATE INDEX idx_lld_child_rule ON lld_child_anomalies(ruleid);
        CREATE INDEX idx_lld_child_reason ON lld_child_anomalies(reason);

        CREATE TABLE host_summary (
            hostid INTEGER,
            host TEXT,
            host_name TEXT,
            category TEXT,
            severity TEXT,
            anomaly_count INTEGER,
            PRIMARY KEY(hostid, category)
        );
        """
    )
    return conn


def _insert_rows(conn: sqlite3.Connection, table: str, columns: list[str], rows: Iterable[dict[str, Any]], batch_size: int = 10000) -> int:
    sql = f"INSERT OR REPLACE INTO {table} ({','.join(columns)}) VALUES ({','.join(['?'] * len(columns))})"
    batch: list[tuple[Any, ...]] = []
    total = 0
    for row in rows:
        batch.append(tuple(row.get(col) for col in columns))
        if len(batch) >= batch_size:
            conn.executemany(sql, batch)
            conn.commit()
            total += len(batch)
            batch.clear()
    if batch:
        conn.executemany(sql, batch)
        conn.commit()
        total += len(batch)
    return total


def _iter_sqlite_ids(conn: sqlite3.Connection, sql: str) -> Iterable[int]:
    cur = conn.execute(sql)
    for row in cur:
        yield int(row[0])


def _load_current_baseline_objects(
    conn: sqlite3.Connection,
    db: MySQLDatabase,
    report_cfg: ReportConfig,
) -> None:
    item_insert = f"INSERT OR REPLACE INTO current_items ({','.join(ITEM_COLUMNS)}) VALUES ({','.join(['?'] * len(ITEM_COLUMNS))})"
    disc_insert = f"INSERT OR REPLACE INTO current_discovery ({','.join(DISCOVERY_COLUMNS)}) VALUES ({','.join(['?'] * len(DISCOVERY_COLUMNS))})"

    processed = 0
    item_ids = _iter_sqlite_ids(conn, "SELECT itemid FROM baseline.items ORDER BY itemid")
    for ids in chunks(item_ids, report_cfg.batch_size):
        rows = db.fetch_items(ids)
        if rows:
            conn.executemany(item_insert, [tuple(row.get(c) for c in ITEM_COLUMNS) for row in rows])
        disc_rows = db.fetch_discovery(ids)
        if disc_rows:
            conn.executemany(disc_insert, [tuple(row.get(c) for c in DISCOVERY_COLUMNS) for row in disc_rows])
        conn.commit()
        processed += len(ids)
        if processed % 100000 < report_cfg.batch_size:
            LOG.info("Zabbix 7: %s IDs do baseline verificados", f"{processed:,}")

    host_insert = "INSERT OR REPLACE INTO current_hosts(hostid,host,host_name,host_status,proxy_ref) VALUES (?,?,?,?,?)"
    processed_hosts = 0
    host_ids = _iter_sqlite_ids(conn, "SELECT DISTINCT hostid FROM baseline.items WHERE hostid IS NOT NULL ORDER BY hostid")
    for ids in chunks(host_ids, report_cfg.batch_size):
        rows = db.fetch_hosts(ids)
        if rows:
            conn.executemany(
                host_insert,
                [(r.get("hostid"), r.get("host"), r.get("host_name"), r.get("host_status"), r.get("proxy_ref")) for r in rows],
            )
        conn.commit()
        processed_hosts += len(ids)
    LOG.info("Zabbix 7: %s hosts do baseline verificados", f"{processed_hosts:,}")


def _current_alias_select(prefix: str = "c_") -> str:
    return ", ".join(f"c.`{col}` AS `{prefix}{col}`" for col in ITEM_COLUMNS)


def _row_to_current(row: sqlite3.Row, prefix: str = "c_") -> dict[str, Any] | None:
    if row[f"{prefix}itemid"] is None:
        return None
    return {col: row[f"{prefix}{col}"] for col in ITEM_COLUMNS}


def _analyze_items(conn: sqlite3.Connection) -> int:
    sql = f"""
        SELECT b.*, {_current_alias_select()}, ch.hostid AS current_host_exists
        FROM baseline.items b
        LEFT JOIN current_items c ON c.itemid = b.itemid
        LEFT JOIN current_hosts ch ON ch.hostid = b.hostid
        WHERE b.host_status = 0
          AND b.item_status = 0
          AND b.rt_state = 0
          AND b.flags IN (0, 4)
        ORDER BY b.itemid
    """
    insert_sql = f"INSERT INTO anomalies ({','.join(ANOMALY_COLUMNS)}) VALUES ({','.join(['?'] * len(ANOMALY_COLUMNS))})"
    batch: list[tuple[Any, ...]] = []
    anomaly_count = 0
    analyzed = 0

    cur = conn.execute(sql)
    for row in cur:
        b = {col: row[col] for col in ITEM_COLUMNS}
        c = _row_to_current(row)
        category, severity = classify_item(b, c, current_host_exists=row["current_host_exists"] is not None)
        analyzed += 1
        if category == "OK":
            continue

        changed = structural_diff(b, c) if c else []
        current_error = None
        current_if_error = None
        if c:
            current_error = c.get("rt_error") or c.get("interface_error")
            current_if_error = c.get("interface_error")
        master_itemid = c.get("master_itemid") if c is not None else b.get("master_itemid")
        values = {
            "itemid": b["itemid"],
            "hostid": b["hostid"],
            "host": b["host"],
            "host_name": b["host_name"],
            "item_name": b["name"],
            "key_": b["key_"],
            "category": category,
            "severity": severity,
            "baseline_rt_state": b["rt_state"],
            "current_rt_state": c.get("rt_state") if c else None,
            "current_error": current_error,
            "baseline_item_status": b["item_status"],
            "current_item_status": c.get("item_status") if c else None,
            "baseline_interface_available": b.get("interface_available"),
            "current_interface_available": c.get("interface_available") if c else None,
            "current_interface_error": current_if_error,
            "baseline_proxy_ref": b.get("proxy_ref"),
            "current_proxy_ref": c.get("proxy_ref") if c else None,
            "master_itemid": master_itemid,
            "master_anomaly_itemid": None,
            "master_anomaly_category": None,
            "dependent_affected_count": 0,
            "changed_fields": ",".join(changed),
        }
        batch.append(tuple(values[col] for col in ANOMALY_COLUMNS))
        anomaly_count += 1
        if len(batch) >= 10000:
            conn.executemany(insert_sql, batch)
            conn.commit()
            batch.clear()

    if batch:
        conn.executemany(insert_sql, batch)
        conn.commit()

    conn.execute("INSERT OR REPLACE INTO metadata(key,value) VALUES (?,?)", ("baseline_healthy_items_analyzed", json.dumps(analyzed)))
    conn.commit()
    LOG.info("Itens: %s saudáveis no baseline; %s regressões", f"{analyzed:,}", f"{anomaly_count:,}")
    return anomaly_count


def _analyze_lld_rules(conn: sqlite3.Connection) -> int:
    sql = f"""
        SELECT b.*, {_current_alias_select()}, ch.hostid AS current_host_exists
        FROM baseline.items b
        LEFT JOIN current_items c ON c.itemid = b.itemid
        LEFT JOIN current_hosts ch ON ch.hostid = b.hostid
        WHERE b.host_status = 0
          AND b.item_status = 0
          AND b.rt_state = 0
          AND b.flags = 1
        ORDER BY b.itemid
    """
    insert_sql = f"INSERT INTO lld_rule_anomalies ({','.join(LLD_RULE_COLUMNS)}) VALUES ({','.join(['?'] * len(LLD_RULE_COLUMNS))})"
    batch: list[tuple[Any, ...]] = []
    anomaly_count = 0
    analyzed = 0

    for row in conn.execute(sql):
        b = {col: row[col] for col in ITEM_COLUMNS}
        c = _row_to_current(row)
        category, severity = classify_lld_rule(b, c, current_host_exists=row["current_host_exists"] is not None)
        analyzed += 1
        if category == "OK":
            continue
        changed = structural_diff(b, c) if c else []
        values = {
            "itemid": b["itemid"],
            "hostid": b["hostid"],
            "host": b["host"],
            "host_name": b["host_name"],
            "rule_name": b["name"],
            "key_": b["key_"],
            "category": category,
            "severity": severity,
            "baseline_rt_state": b["rt_state"],
            "current_rt_state": c.get("rt_state") if c else None,
            "current_error": (c.get("rt_error") or c.get("interface_error")) if c else None,
            "baseline_item_status": b["item_status"],
            "current_item_status": c.get("item_status") if c else None,
            "changed_fields": ",".join(changed),
        }
        batch.append(tuple(values[col] for col in LLD_RULE_COLUMNS))
        anomaly_count += 1
        if len(batch) >= 5000:
            conn.executemany(insert_sql, batch)
            conn.commit()
            batch.clear()
    if batch:
        conn.executemany(insert_sql, batch)
        conn.commit()

    conn.execute("INSERT OR REPLACE INTO metadata(key,value) VALUES (?,?)", ("baseline_healthy_lld_rules_analyzed", json.dumps(analyzed)))
    conn.commit()
    LOG.info("LLD rules: %s saudáveis no baseline; %s regressões", f"{analyzed:,}", f"{anomaly_count:,}")
    return anomaly_count


def _build_lld_map(conn: sqlite3.Connection) -> int:
    conn.execute("DELETE FROM lld_baseline_map")
    conn.execute(
        """
        INSERT INTO lld_baseline_map(itemid, prototypeid, ruleid, group_id, baseline_item_status)
        SELECT
            child.itemid,
            child.parent_itemid AS prototypeid,
            CASE WHEN rule.flags = 1 THEN proto.parent_itemid ELSE NULL END AS ruleid,
            CASE WHEN rule.flags = 1 THEN proto.parent_itemid ELSE -child.parent_itemid END AS group_id,
            ci.item_status
        FROM baseline.discovery child
        JOIN baseline.items ci ON ci.itemid = child.itemid AND ci.flags = 4
        LEFT JOIN baseline.discovery proto ON proto.itemid = child.parent_itemid
        LEFT JOIN baseline.items rule ON rule.itemid = proto.parent_itemid
        WHERE COALESCE(child.ts_delete, 0) = 0
          AND COALESCE(child.discovery_status, 0) = 0
        """
    )
    conn.commit()
    count = conn.execute("SELECT COUNT(*) FROM lld_baseline_map").fetchone()[0]
    unresolved = conn.execute("SELECT COUNT(*) FROM lld_baseline_map WHERE ruleid IS NULL").fetchone()[0]
    LOG.info("LLD: %s filhos válidos no baseline; %s sem regra resolvida", f"{count:,}", f"{unresolved:,}")
    return count


def _build_lld_child_details(conn: sqlite3.Connection) -> int:
    conn.execute("DELETE FROM lld_child_anomalies")
    conn.execute(
        """
        INSERT INTO lld_child_anomalies(
            itemid,prototypeid,ruleid,group_id,hostid,host,item_name,key_,reason,current_item_status,
            discovery_status,ts_delete,ts_disable,disable_source
        )
        SELECT
            m.itemid,
            m.prototypeid,
            m.ruleid,
            m.group_id,
            b.hostid,
            b.host,
            b.name,
            b.key_,
            CASE
                WHEN c.itemid IS NULL THEN 'MISSING'
                WHEN cd.itemid IS NULL THEN 'DISCOVERY_METADATA_MISSING'
                WHEN COALESCE(cd.discovery_status,0) = 1 THEN 'NOT_DISCOVERED'
                WHEN COALESCE(cd.ts_delete,0) > 0 THEN 'PENDING_DELETE'
                WHEN m.baseline_item_status = 0 AND c.item_status <> 0 THEN 'DISABLED'
                WHEN m.baseline_item_status = 0 AND COALESCE(cd.ts_disable,0) > 0 THEN 'PENDING_DISABLE'
                ELSE 'PRESENT'
            END AS reason,
            c.item_status,
            cd.discovery_status,
            cd.ts_delete,
            cd.ts_disable,
            cd.disable_source
        FROM lld_baseline_map m
        JOIN baseline.items b ON b.itemid = m.itemid
        LEFT JOIN current_items c ON c.itemid = m.itemid
        LEFT JOIN current_discovery cd ON cd.itemid = m.itemid
        WHERE
            c.itemid IS NULL
            OR cd.itemid IS NULL
            OR COALESCE(cd.discovery_status,0) = 1
            OR COALESCE(cd.ts_delete,0) > 0
            OR (m.baseline_item_status = 0 AND c.item_status <> 0)
            OR (m.baseline_item_status = 0 AND COALESCE(cd.ts_disable,0) > 0)
        """
    )
    conn.commit()
    return conn.execute("SELECT COUNT(*) FROM lld_child_anomalies").fetchone()[0]


def _analyze_lld_counts(conn: sqlite3.Connection, report_cfg: ReportConfig) -> int:
    # Aggregate first; this is substantially faster than pulling millions of children into Python.
    raw_sql = """
        SELECT
            m.group_id,
            MAX(m.ruleid) AS ruleid,
            MAX(m.prototypeid) AS prototypeid,
            COUNT(*) AS baseline_count,
            SUM(CASE WHEN
                c.itemid IS NOT NULL
                AND cd.itemid IS NOT NULL
                AND COALESCE(cd.discovery_status,0) <> 1
                AND COALESCE(cd.ts_delete,0) = 0
                THEN 1 ELSE 0 END) AS current_present_count,
            SUM(CASE WHEN c.itemid IS NULL THEN 1 ELSE 0 END) AS missing_count,
            SUM(CASE WHEN c.itemid IS NOT NULL AND cd.itemid IS NULL THEN 1 ELSE 0 END) AS metadata_missing_count,
            SUM(CASE WHEN cd.itemid IS NOT NULL AND COALESCE(cd.discovery_status,0) = 1 THEN 1 ELSE 0 END) AS not_discovered_count,
            SUM(CASE WHEN cd.itemid IS NOT NULL AND COALESCE(cd.ts_delete,0) > 0 THEN 1 ELSE 0 END) AS pending_delete_count,
            SUM(CASE WHEN m.baseline_item_status = 0 THEN 1 ELSE 0 END) AS baseline_operational_count,
            SUM(CASE WHEN
                m.baseline_item_status = 0
                AND c.itemid IS NOT NULL
                AND cd.itemid IS NOT NULL
                AND COALESCE(cd.discovery_status,0) <> 1
                AND COALESCE(cd.ts_delete,0) = 0
                AND c.item_status = 0
                AND COALESCE(cd.ts_disable,0) = 0
                THEN 1 ELSE 0 END) AS current_operational_count,
            SUM(CASE WHEN
                m.baseline_item_status = 0
                AND c.itemid IS NOT NULL
                AND cd.itemid IS NOT NULL
                AND COALESCE(cd.discovery_status,0) <> 1
                AND COALESCE(cd.ts_delete,0) = 0
                AND c.item_status <> 0
                THEN 1 ELSE 0 END) AS disabled_count,
            SUM(CASE WHEN
                m.baseline_item_status = 0
                AND c.itemid IS NOT NULL
                AND cd.itemid IS NOT NULL
                AND COALESCE(cd.discovery_status,0) <> 1
                AND COALESCE(cd.ts_delete,0) = 0
                AND COALESCE(cd.ts_disable,0) > 0
                THEN 1 ELSE 0 END) AS pending_disable_count
        FROM lld_baseline_map m
        LEFT JOIN current_items c ON c.itemid = m.itemid
        LEFT JOIN current_discovery cd ON cd.itemid = m.itemid
        GROUP BY m.group_id
        ORDER BY m.group_id
    """

    insert_sql = """
        INSERT INTO lld_summary(
            group_id,ruleid,prototypeid,hostid,host,host_name,rule_name,rule_key,mapping_status,
            baseline_count,current_present_count,lost_count,loss_pct,baseline_operational_count,
            current_operational_count,operational_lost_count,operational_loss_pct,missing_count,
            metadata_missing_count,not_discovered_count,pending_delete_count,disabled_count,
            pending_disable_count,category,severity
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """
    conn.execute("DELETE FROM lld_summary")
    batch: list[tuple[Any, ...]] = []
    anomaly_groups = 0

    for row in conn.execute(raw_sql):
        group_id = row["group_id"]
        ruleid = row["ruleid"]
        prototypeid = row["prototypeid"]
        identity_id = ruleid if ruleid is not None else prototypeid
        identity = conn.execute(
            "SELECT itemid,hostid,host,host_name,name,key_ FROM baseline.items WHERE itemid=?",
            (identity_id,),
        ).fetchone()

        discovery_sev, loss_pct, lost_count = loss_severity(
            row["baseline_count"], row["current_present_count"], report_cfg.thresholds
        )
        op_sev, op_loss_pct, op_lost_count = loss_severity(
            row["baseline_operational_count"], row["current_operational_count"], report_cfg.thresholds
        )
        severity = discovery_sev if SEVERITY_RANK[discovery_sev] >= SEVERITY_RANK[op_sev] else op_sev

        if discovery_sev == "CRITICAL" and row["current_present_count"] == 0 and row["baseline_count"] > 0:
            category = "LLD_TOTAL_LOSS"
        elif discovery_sev != "OK" and op_sev != "OK":
            category = "LLD_CHILD_AND_OPERATIONAL_LOSS"
        elif discovery_sev != "OK":
            category = "LLD_CHILD_LOSS"
        elif op_sev != "OK":
            category = "LLD_OPERATIONAL_LOSS"
        else:
            category = "OK"

        if category != "OK":
            anomaly_groups += 1

        batch.append(
            (
                group_id,
                ruleid,
                prototypeid,
                identity["hostid"] if identity else None,
                identity["host"] if identity else None,
                identity["host_name"] if identity else None,
                identity["name"] if identity else None,
                identity["key_"] if identity else None,
                "RULE_RESOLVED" if ruleid is not None else "PROTOTYPE_FALLBACK",
                row["baseline_count"],
                row["current_present_count"],
                lost_count,
                loss_pct,
                row["baseline_operational_count"],
                row["current_operational_count"],
                op_lost_count,
                op_loss_pct,
                row["missing_count"],
                row["metadata_missing_count"],
                row["not_discovered_count"],
                row["pending_delete_count"],
                row["disabled_count"],
                row["pending_disable_count"],
                category,
                severity,
            )
        )
        if len(batch) >= 5000:
            conn.executemany(insert_sql, batch)
            conn.commit()
            batch.clear()
    if batch:
        conn.executemany(insert_sql, batch)
        conn.commit()

    LOG.info("LLD: %s regras/grupos com perda relevante", f"{anomaly_groups:,}")
    return anomaly_groups


def _enrich_dependency_roots(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        UPDATE anomalies
        SET master_anomaly_itemid = (
                SELECT m.itemid FROM anomalies m WHERE m.itemid = anomalies.master_itemid
            ),
            master_anomaly_category = (
                SELECT m.category FROM anomalies m WHERE m.itemid = anomalies.master_itemid
            )
        WHERE master_itemid IS NOT NULL AND master_itemid <> 0
        """
    )
    conn.execute(
        """
        UPDATE anomalies
        SET dependent_affected_count = (
            SELECT COUNT(*) FROM anomalies child WHERE child.master_itemid = anomalies.itemid
        )
        """
    )
    conn.commit()


def _build_host_summary(conn: sqlite3.Connection) -> None:
    conn.execute("DELETE FROM host_summary")
    conn.execute(
        """
        INSERT INTO host_summary(hostid,host,host_name,category,severity,anomaly_count)
        SELECT hostid,host,host_name,category,severity,COUNT(*)
        FROM anomalies
        GROUP BY hostid,host,host_name,category,severity
        """
    )
    conn.commit()


def _metadata(conn: sqlite3.Connection, key: str, value: Any) -> None:
    conn.execute("INSERT OR REPLACE INTO metadata(key,value) VALUES (?,?)", (key, json.dumps(value, ensure_ascii=False)))


def _write_csv(conn: sqlite3.Connection, table: str, path: Path, where: str = "", order_by: str = "") -> None:
    sql = f"SELECT * FROM {table}"
    if where:
        sql += f" WHERE {where}"
    if order_by:
        sql += f" ORDER BY {order_by}"
    cur = conn.execute(sql)
    headers = [desc[0] for desc in cur.description]
    with path.open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(headers)
        while True:
            rows = cur.fetchmany(10000)
            if not rows:
                break
            writer.writerows([tuple(row) for row in rows])


def export_csvs(conn: sqlite3.Connection, output_dir: Path, write_lld_child_details: bool) -> None:
    _write_csv(conn, "anomalies", output_dir / "item_regressions.csv", order_by="CASE severity WHEN 'CRITICAL' THEN 3 WHEN 'HIGH' THEN 2 WHEN 'WARNING' THEN 1 ELSE 0 END DESC, host, itemid")
    _write_csv(conn, "lld_rule_anomalies", output_dir / "lld_rule_regressions.csv", order_by="CASE severity WHEN 'CRITICAL' THEN 3 WHEN 'HIGH' THEN 2 WHEN 'WARNING' THEN 1 ELSE 0 END DESC, host, itemid")
    _write_csv(conn, "lld_summary", output_dir / "lld_loss_summary.csv", order_by="CASE severity WHEN 'CRITICAL' THEN 3 WHEN 'HIGH' THEN 2 WHEN 'WARNING' THEN 1 ELSE 0 END DESC, loss_pct DESC")
    _write_csv(conn, "host_summary", output_dir / "host_summary.csv", order_by="anomaly_count DESC")
    _write_csv(conn, "template_summary", output_dir / "template_summary.csv", order_by="rank ASC")
    if write_lld_child_details:
        _write_csv(conn, "lld_child_anomalies", output_dir / "lld_child_anomalies.csv", order_by="ruleid, reason, itemid")


def compare_snapshot_to_current(
    baseline_path: str | Path,
    db: MySQLDatabase,
    output_dir: str | Path,
    report_cfg: ReportConfig,
    force: bool = False,
) -> tuple[Path, dict[str, Any]]:
    baseline_path = Path(baseline_path)
    if not baseline_path.exists():
        raise FileNotFoundError(f"Snapshot baseline não encontrado: {baseline_path}")

    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    result_db = output / "comparison_results.sqlite"

    errors = db.validate_required_schema()
    if errors:
        raise RuntimeError("Schema Zabbix atual inválido:\n- " + "\n- ".join(errors))

    baseline_meta = read_metadata(baseline_path)
    conn = _create_results_db(result_db, baseline_path, force=force)
    try:
        current_version = db.db_version()
        _metadata(conn, "checker_version", __version__)
        _metadata(conn, "created_at_utc", datetime.now(timezone.utc).isoformat())
        _metadata(conn, "baseline_metadata", baseline_meta)
        _metadata(conn, "current_dbversion", current_version)
        _metadata(conn, "current_host", db.cfg.host)
        _metadata(conn, "current_database", db.cfg.database)
        _metadata(conn, "thresholds", {
            "warning_loss_pct": report_cfg.warning_loss_pct,
            "high_loss_pct": report_cfg.high_loss_pct,
            "min_absolute_loss": report_cfg.min_absolute_loss,
        })
        conn.commit()

        LOG.info("Carregando no comparador somente IDs existentes no Zabbix 6; itens novos do 7 serão ignorados.")
        _load_current_baseline_objects(conn, db, report_cfg)
        _analyze_items(conn)
        _analyze_lld_rules(conn)
        _build_lld_map(conn)
        if report_cfg.write_lld_child_details:
            child_anomalies = _build_lld_child_details(conn)
            _metadata(conn, "lld_child_anomaly_count", child_anomalies)
        _analyze_lld_counts(conn, report_cfg)
        _enrich_dependency_roots(conn)
        _build_host_summary(conn)
        enrich_template_groups(conn, baseline_alias="baseline")

        summary = {
            "baseline_item_count": conn.execute("SELECT COUNT(*) FROM baseline.items").fetchone()[0],
            "baseline_healthy_items_analyzed": conn.execute("SELECT COUNT(*) FROM baseline.items WHERE host_status=0 AND item_status=0 AND rt_state=0 AND flags IN (0,4)").fetchone()[0],
            "item_regressions": conn.execute("SELECT COUNT(*) FROM anomalies").fetchone()[0],
            "lld_rule_regressions": conn.execute("SELECT COUNT(*) FROM lld_rule_anomalies").fetchone()[0],
            "lld_groups_with_loss": conn.execute("SELECT COUNT(*) FROM lld_summary WHERE category <> 'OK'").fetchone()[0],
            "lld_total_loss": conn.execute("SELECT COUNT(*) FROM lld_summary WHERE category='LLD_TOTAL_LOSS'").fetchone()[0],
            "hosts_impacted": conn.execute("SELECT COUNT(DISTINCT hostid) FROM anomalies").fetchone()[0],
            "templates_impacted": conn.execute("SELECT COUNT(*) FROM template_summary").fetchone()[0],
            "categories": {row[0]: row[1] for row in conn.execute("SELECT category,COUNT(*) FROM anomalies GROUP BY category ORDER BY COUNT(*) DESC")},
            "lld_rule_categories": {row[0]: row[1] for row in conn.execute("SELECT category,COUNT(*) FROM lld_rule_anomalies GROUP BY category ORDER BY COUNT(*) DESC")},
        }
        _metadata(conn, "summary", summary)
        conn.commit()

        export_csvs(conn, output, report_cfg.write_lld_child_details)
        (output / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
        conn.execute("PRAGMA optimize")
    finally:
        conn.close()

    LOG.info("Comparação concluída: %s", output)
    return result_db, summary
