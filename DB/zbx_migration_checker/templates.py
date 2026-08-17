from __future__ import annotations

import json
import logging
import sqlite3
from pathlib import Path
from typing import Any


LOG = logging.getLogger(__name__)


def open_sqlite(path: str | Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA temp_store=MEMORY")
    return conn

_TEMPLATE_COLUMNS = [
    ("direct_template_itemid", "INTEGER"),
    ("direct_template_hostid", "INTEGER"),
    ("direct_template_host", "TEXT"),
    ("direct_template_name", "TEXT"),
    ("base_template_itemid", "INTEGER"),
    ("base_template_hostid", "INTEGER"),
    ("base_template_host", "TEXT"),
    ("base_template_name", "TEXT"),
    ("template_depth", "INTEGER"),
    ("template_chain_complete", "INTEGER"),
]


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}


def _ensure_column(conn: sqlite3.Connection, table: str, column: str, decl: str) -> None:
    if column not in _columns(conn, table):
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")


def _ensure_schema(conn: sqlite3.Connection) -> None:
    for table in ("anomalies", "lld_rule_anomalies", "lld_summary"):
        for name, decl in _TEMPLATE_COLUMNS:
            _ensure_column(conn, table, name, decl)

    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS template_item_map (
            itemid INTEGER PRIMARY KEY,
            direct_template_itemid INTEGER,
            direct_template_hostid INTEGER,
            direct_template_host TEXT,
            direct_template_name TEXT,
            base_template_itemid INTEGER,
            base_template_hostid INTEGER,
            base_template_host TEXT,
            base_template_name TEXT,
            template_depth INTEGER,
            template_chain_complete INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_template_item_map_base ON template_item_map(base_template_hostid);

        CREATE TABLE IF NOT EXISTS template_summary (
            rank INTEGER,
            template_hostid INTEGER PRIMARY KEY,
            template_host TEXT,
            template_name TEXT,
            priority_score INTEGER,
            impact_count INTEGER,
            hosts_affected INTEGER,
            item_regressions INTEGER,
            lld_rule_regressions INTEGER,
            lld_groups_with_loss INTEGER,
            lld_total_loss INTEGER,
            lld_lost_children INTEGER,
            lld_pending_delete INTEGER,
            dependent_affected INTEGER,
            critical_count INTEGER,
            high_count INTEGER,
            warning_count INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_template_summary_rank ON template_summary(rank);
        CREATE INDEX IF NOT EXISTS idx_template_summary_score ON template_summary(priority_score);
        """
    )
    conn.commit()


def _build_target_map(conn: sqlite3.Connection, baseline_alias: str = "baseline") -> int:
    """Resolve direct and root/base templates only for objects that appear in results.

    Zabbix item inheritance is followed through items.templateid. The root-most
    inherited item determines the base template. Local/non-inherited items are
    intentionally left with base_template_hostid NULL.
    """
    conn.execute("DELETE FROM template_item_map")
    conn.execute("DROP TABLE IF EXISTS temp._template_targets")
    conn.execute("CREATE TEMP TABLE _template_targets(itemid INTEGER PRIMARY KEY)")
    conn.executescript(
        """
        INSERT OR IGNORE INTO _template_targets SELECT itemid FROM anomalies WHERE itemid IS NOT NULL;
        INSERT OR IGNORE INTO _template_targets SELECT itemid FROM lld_rule_anomalies WHERE itemid IS NOT NULL;
        INSERT OR IGNORE INTO _template_targets SELECT ruleid FROM lld_summary WHERE ruleid IS NOT NULL;
        INSERT OR IGNORE INTO _template_targets SELECT prototypeid FROM lld_summary WHERE prototypeid IS NOT NULL;
        """
    )

    sql = f"""
        WITH RECURSIVE chain(
            origin_itemid,current_itemid,next_templateid,hostid,host,host_name,depth,path
        ) AS (
            SELECT t.itemid,b.itemid,b.templateid,b.hostid,b.host,b.host_name,0,
                   ',' || CAST(b.itemid AS TEXT) || ','
            FROM _template_targets t
            JOIN {baseline_alias}.items b ON b.itemid=t.itemid

            UNION ALL

            SELECT c.origin_itemid,p.itemid,p.templateid,p.hostid,p.host,p.host_name,c.depth+1,
                   c.path || CAST(p.itemid AS TEXT) || ','
            FROM chain c
            JOIN {baseline_alias}.items p ON p.itemid=c.next_templateid
            WHERE COALESCE(c.next_templateid,0)<>0
              AND c.depth<64
              AND instr(c.path, ',' || CAST(p.itemid AS TEXT) || ',')=0
        )
        SELECT origin_itemid,current_itemid,next_templateid,hostid,host,host_name,depth
        FROM chain
        ORDER BY origin_itemid,depth
    """

    insert = """
        INSERT OR REPLACE INTO template_item_map(
            itemid,direct_template_itemid,direct_template_hostid,direct_template_host,direct_template_name,
            base_template_itemid,base_template_hostid,base_template_host,base_template_name,
            template_depth,template_chain_complete
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?)
    """

    count = 0
    origin: int | None = None
    rows: list[sqlite3.Row] = []

    def flush(group: list[sqlite3.Row]) -> None:
        nonlocal count
        if not group:
            return
        first = group[0]
        # No inheritance means a host-local item. Do not call the monitored host a template.
        inherited = int(first["next_templateid"] or 0) != 0
        if not inherited:
            conn.execute(insert, (first["origin_itemid"], None, None, None, None, None, None, None, None, 0, 1))
            count += 1
            return

        direct = group[1] if len(group) > 1 else None
        base = group[-1] if len(group) > 1 else None
        complete = 1 if base is not None and int(base["next_templateid"] or 0) == 0 else 0
        conn.execute(
            insert,
            (
                first["origin_itemid"],
                direct["current_itemid"] if direct else None,
                direct["hostid"] if direct else None,
                direct["host"] if direct else None,
                direct["host_name"] if direct else None,
                base["current_itemid"] if base is not None and complete else None,
                base["hostid"] if base is not None and complete else None,
                base["host"] if base is not None and complete else None,
                base["host_name"] if base is not None and complete else None,
                int(base["depth"] if base else 0),
                complete,
            ),
        )
        count += 1

    cur = conn.execute(sql)
    for row in cur:
        oid = int(row["origin_itemid"])
        if origin is None:
            origin = oid
        if oid != origin:
            flush(rows)
            rows = []
            origin = oid
        rows.append(row)
    flush(rows)
    conn.commit()
    return count


def _apply_map(conn: sqlite3.Connection) -> None:
    assignments = ",\n".join(
        f"{col}=(SELECT {col} FROM template_item_map m WHERE m.itemid={{origin}})" for col, _ in _TEMPLATE_COLUMNS
    )
    conn.execute(f"UPDATE anomalies SET {assignments.format(origin='anomalies.itemid')}")
    conn.execute(f"UPDATE lld_rule_anomalies SET {assignments.format(origin='lld_rule_anomalies.itemid')}")

    # Discovery rule is preferred. Prototype is a fallback for unusual/malformed mappings.
    lld_assignments = ",\n".join(
        f"{col}=COALESCE((SELECT {col} FROM template_item_map m WHERE m.itemid=lld_summary.ruleid),"
        f"(SELECT {col} FROM template_item_map m WHERE m.itemid=lld_summary.prototypeid))"
        for col, _ in _TEMPLATE_COLUMNS
    )
    conn.execute(f"UPDATE lld_summary SET {lld_assignments}")
    conn.commit()


def _summary_row(store: dict[int, dict[str, Any]], hostid: int, host: str | None, name: str | None) -> dict[str, Any]:
    if hostid not in store:
        store[hostid] = {
            "template_hostid": hostid,
            "template_host": host or "",
            "template_name": name or host or f"Template {hostid}",
            "hosts": set(),
            "item_regressions": 0,
            "lld_rule_regressions": 0,
            "lld_groups_with_loss": 0,
            "lld_total_loss": 0,
            "lld_lost_children": 0,
            "lld_pending_delete": 0,
            "dependent_affected": 0,
            "critical_count": 0,
            "high_count": 0,
            "warning_count": 0,
        }
    return store[hostid]


def _build_summary(conn: sqlite3.Connection) -> int:
    store: dict[int, dict[str, Any]] = {}

    for row in conn.execute(
        """
        SELECT base_template_hostid,base_template_host,base_template_name,hostid,severity,
               COUNT(*) n,COALESCE(SUM(dependent_affected_count),0) deps
        FROM anomalies
        WHERE base_template_hostid IS NOT NULL
        GROUP BY base_template_hostid,base_template_host,base_template_name,hostid,severity
        """
    ):
        s = _summary_row(store, int(row[0]), row[1], row[2])
        if row[3] is not None:
            s["hosts"].add(int(row[3]))
        n = int(row[5] or 0)
        s["item_regressions"] += n
        s["dependent_affected"] += int(row[6] or 0)
        key = {"CRITICAL": "critical_count", "HIGH": "high_count", "WARNING": "warning_count"}.get(row[4])
        if key:
            s[key] += n

    for row in conn.execute(
        """
        SELECT base_template_hostid,base_template_host,base_template_name,hostid,severity,COUNT(*) n
        FROM lld_rule_anomalies
        WHERE base_template_hostid IS NOT NULL
        GROUP BY base_template_hostid,base_template_host,base_template_name,hostid,severity
        """
    ):
        s = _summary_row(store, int(row[0]), row[1], row[2])
        if row[3] is not None:
            s["hosts"].add(int(row[3]))
        n = int(row[5] or 0)
        s["lld_rule_regressions"] += n
        key = {"CRITICAL": "critical_count", "HIGH": "high_count", "WARNING": "warning_count"}.get(row[4])
        if key:
            s[key] += n

    for row in conn.execute(
        """
        SELECT base_template_hostid,base_template_host,base_template_name,hostid,severity,category,
               COUNT(*) groups_count,COALESCE(SUM(lost_count),0) lost,
               COALESCE(SUM(pending_delete_count),0) pending_delete
        FROM lld_summary
        WHERE base_template_hostid IS NOT NULL AND category<>'OK'
        GROUP BY base_template_hostid,base_template_host,base_template_name,hostid,severity,category
        """
    ):
        s = _summary_row(store, int(row[0]), row[1], row[2])
        if row[3] is not None:
            s["hosts"].add(int(row[3]))
        groups = int(row[6] or 0)
        s["lld_groups_with_loss"] += groups
        if row[5] == "LLD_TOTAL_LOSS":
            s["lld_total_loss"] += groups
        s["lld_lost_children"] += int(row[7] or 0)
        s["lld_pending_delete"] += int(row[8] or 0)
        key = {"CRITICAL": "critical_count", "HIGH": "high_count", "WARNING": "warning_count"}.get(row[4])
        if key:
            s[key] += groups

    ranked: list[dict[str, Any]] = []
    for s in store.values():
        # Directly impacted objects. dependent_affected is kept as context but is
        # not added here because those dependent items are normally already
        # represented in item_regressions and would otherwise be double counted.
        impact = (
            s["item_regressions"]
            + s["lld_rule_regressions"]
            + s["lld_lost_children"]
        )
        # Severity dominates the ordering; impact breaks ties and emphasizes mass regressions.
        score = (
            s["lld_total_loss"] * 1_000_000
            + s["critical_count"] * 100_000
            + s["high_count"] * 10_000
            + s["warning_count"] * 1_000
            + min(int(impact), 999)
        )
        s["impact_count"] = int(impact)
        s["priority_score"] = int(score)
        s["hosts_affected"] = len(s.pop("hosts"))
        ranked.append(s)

    ranked.sort(key=lambda x: (-x["priority_score"], -x["impact_count"], x["template_name"].lower()))
    conn.execute("DELETE FROM template_summary")
    insert = """
        INSERT INTO template_summary(
            rank,template_hostid,template_host,template_name,priority_score,impact_count,hosts_affected,
            item_regressions,lld_rule_regressions,lld_groups_with_loss,lld_total_loss,lld_lost_children,
            lld_pending_delete,dependent_affected,critical_count,high_count,warning_count
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """
    for rank, s in enumerate(ranked, 1):
        conn.execute(
            insert,
            (
                rank, s["template_hostid"], s["template_host"], s["template_name"], s["priority_score"],
                s["impact_count"], s["hosts_affected"], s["item_regressions"], s["lld_rule_regressions"],
                s["lld_groups_with_loss"], s["lld_total_loss"], s["lld_lost_children"], s["lld_pending_delete"],
                s["dependent_affected"], s["critical_count"], s["high_count"], s["warning_count"],
            ),
        )
    conn.commit()
    return len(ranked)


def enrich_template_groups(conn: sqlite3.Connection, baseline_alias: str = "baseline") -> dict[str, Any]:
    _ensure_schema(conn)
    mapped = _build_target_map(conn, baseline_alias=baseline_alias)
    _apply_map(conn)
    templates = _build_summary(conn)

    unmapped_items = conn.execute(
        "SELECT COUNT(*) FROM anomalies WHERE base_template_hostid IS NULL"
    ).fetchone()[0]
    result = {
        "mapped_objects": mapped,
        "templates_impacted": templates,
        "unmapped_or_local_item_regressions": int(unmapped_items or 0),
    }
    conn.execute(
        "INSERT OR REPLACE INTO metadata(key,value) VALUES (?,?)",
        ("template_enrichment", json.dumps(result, ensure_ascii=False)),
    )
    # Update summary metadata when it already exists.
    row = conn.execute("SELECT value FROM metadata WHERE key='summary'").fetchone()
    if row:
        try:
            summary = json.loads(row[0])
            if isinstance(summary, dict):
                summary["templates_impacted"] = templates
                top = conn.execute(
                    "SELECT template_hostid,template_name,impact_count,priority_score FROM template_summary ORDER BY rank LIMIT 1"
                ).fetchone()
                summary["top_template"] = dict(top) if top else None
                conn.execute(
                    "INSERT OR REPLACE INTO metadata(key,value) VALUES ('summary',?)",
                    (json.dumps(summary, ensure_ascii=False),),
                )
        except Exception:
            LOG.warning("Não foi possível atualizar metadata.summary com dados de templates.")
    conn.commit()
    LOG.info("Templates: %s templates base impactados; %s objetos mapeados", templates, mapped)
    return result


def enrich_existing_results(results_path: str | Path, baseline_path: str | Path) -> dict[str, Any]:
    results = Path(results_path).expanduser().resolve()
    if results.is_dir():
        results = results / "comparison_results.sqlite"
    baseline = Path(baseline_path).expanduser().resolve()
    if not results.exists():
        raise FileNotFoundError(f"Banco de resultados não encontrado: {results}")
    if not baseline.exists():
        raise FileNotFoundError(f"Snapshot baseline não encontrado: {baseline}")

    conn = open_sqlite(results)
    try:
        conn.execute("ATTACH DATABASE ? AS baseline", (str(baseline),))
        base_cols = {row[1] for row in conn.execute("PRAGMA baseline.table_info(items)")}
        if not {"itemid", "templateid", "hostid", "host", "host_name"}.issubset(base_cols):
            raise RuntimeError("O snapshot baseline não contém as colunas necessárias para resolver templates.")
        result = enrich_template_groups(conn, baseline_alias="baseline")
        csv_path = results.parent / "template_summary.csv"
        cur = conn.execute("SELECT * FROM template_summary ORDER BY rank")
        headers = [d[0] for d in cur.description]
        import csv
        with csv_path.open("w", encoding="utf-8-sig", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(headers)
            w.writerows([tuple(r) for r in cur.fetchall()])
        result["template_summary_csv"] = str(csv_path)
        return result
    finally:
        conn.close()
