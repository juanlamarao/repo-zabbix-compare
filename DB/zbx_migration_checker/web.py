from __future__ import annotations

import argparse
import json
import mimetypes
import sqlite3
import urllib.parse
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


SEVERITY_EXPR = "CASE severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'WARNING' THEN 2 ELSE 1 END"

ITEM_SORTS = {
    "severity": SEVERITY_EXPR,
    "base_template_name": "base_template_name",
    "host_name": "COALESCE(NULLIF(host_name,''),host)",
    "itemid": "itemid",
    "item_name": "item_name",
    "key_": "key_",
    "category": "category",
    "current_error": "current_error",
    "baseline_item_type": "baseline_item_type",
    "current_item_type": "current_item_type",
    "current_key_": "current_key_",
    "master_itemid": "master_itemid",
    "dependent_affected_count": "dependent_affected_count",
    "changed_fields": "changed_fields",
}
ITEM_FILTERS = {k: v for k, v in ITEM_SORTS.items() if k != "severity"} | {"severity": "severity"}

LLD_SORTS = {
    "severity": SEVERITY_EXPR,
    "base_template_name": "base_template_name",
    "host_name": "COALESCE(NULLIF(host_name,''),host)",
    "ruleid": "ruleid",
    "rule_name": "rule_name",
    "baseline_count": "baseline_count",
    "current_present_count": "current_present_count",
    "lost_count": "lost_count",
    "loss_pct": "loss_pct",
    "operational_loss_pct": "operational_loss_pct",
    "not_discovered_count": "not_discovered_count",
    "pending_delete_count": "pending_delete_count",
    "disabled_count": "disabled_count",
    "category": "category",
}
LLD_FILTERS = {k: v for k, v in LLD_SORTS.items() if k != "severity"} | {"severity": "severity"}

LLD_RULE_SORTS = {
    "severity": SEVERITY_EXPR,
    "base_template_name": "base_template_name",
    "host_name": "COALESCE(NULLIF(host_name,''),host)",
    "itemid": "itemid",
    "rule_name": "rule_name",
    "key_": "key_",
    "category": "category",
    "current_error": "current_error",
    "changed_fields": "changed_fields",
}
LLD_RULE_FILTERS = {k: v for k, v in LLD_RULE_SORTS.items() if k != "severity"} | {"severity": "severity"}

ROOT_SORTS = {
    "severity": SEVERITY_EXPR,
    "base_template_name": "base_template_name",
    "host_name": "COALESCE(NULLIF(host_name,''),host)",
    "itemid": "itemid",
    "item_name": "item_name",
    "category": "category",
    "dependent_affected_count": "dependent_affected_count",
    "current_error": "current_error",
    "changed_fields": "changed_fields",
}
ROOT_FILTERS = {k: v for k, v in ROOT_SORTS.items() if k != "severity"} | {"severity": "severity"}

HOST_SORTS = {
    "host_name": "host_name",
    "anomaly_count": "anomaly_count",
    "critical_count": "critical_count",
    "high_count": "high_count",
    "warning_count": "warning_count",
    "category_count": "category_count",
    "dependent_affected_count": "dependent_affected_count",
}
HOST_FILTERS = {k: k for k in HOST_SORTS}

INTERFACE_HOST_SORTS = {
    "host_name": "host_name",
    "host": "host",
    "hostid": "hostid",
    "interfaceid": "interfaceid",
    "interface_type": "interface_type",
    "interface_main": "interface_main",
    "endpoint": "endpoint",
    "interface_available": "interface_available",
    "interface_error": "interface_error",
    "proxy_ref": "proxy_ref",
    "interface_count": "interface_count",
}
INTERFACE_HOST_FILTERS = {k: k for k in INTERFACE_HOST_SORTS}

TEMPLATE_SORTS = {
    "rank": "rank",
    "template_name": "template_name",
    "impact_count": "impact_count",
    "hosts_affected": "hosts_affected",
    "item_regressions": "item_regressions",
    "critical_count": "critical_count",
    "high_count": "high_count",
    "lld_rule_regressions": "lld_rule_regressions",
    "lld_groups_with_loss": "lld_groups_with_loss",
    "lld_total_loss": "lld_total_loss",
    "lld_lost_children": "lld_lost_children",
    "lld_pending_delete": "lld_pending_delete",
    "dependent_affected": "dependent_affected",
    "priority_score": "priority_score",
    "template_hostid": "template_hostid",
}
TEMPLATE_FILTERS = {k: k for k in TEMPLATE_SORTS}


def _conn(db_path: Path) -> sqlite3.Connection:
    uri = f"file:{db_path.resolve()}?mode=ro"
    conn = sqlite3.connect(uri, uri=True, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def _rows(cur: sqlite3.Cursor) -> list[dict[str, Any]]:
    return [dict(r) for r in cur.fetchall()]


def _scalar(conn: sqlite3.Connection, sql: str, params: tuple[Any, ...] = ()) -> int | float:
    row = conn.execute(sql, params).fetchone()
    return 0 if row is None or row[0] is None else row[0]


def _metadata(conn: sqlite3.Connection) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for row in conn.execute("SELECT key,value FROM metadata"):
        try:
            result[row["key"]] = json.loads(row["value"])
        except Exception:
            result[row["key"]] = row["value"]
    return result


def _status(conn: sqlite3.Connection) -> dict[str, Any]:
    item_critical = _scalar(conn, "SELECT COUNT(*) FROM anomalies WHERE severity='CRITICAL'")
    item_high = _scalar(conn, "SELECT COUNT(*) FROM anomalies WHERE severity='HIGH'")
    lld_critical = _scalar(conn, "SELECT COUNT(*) FROM lld_summary WHERE severity='CRITICAL' AND category<>'OK'")
    lld_rule_critical = _scalar(conn, "SELECT COUNT(*) FROM lld_rule_anomalies WHERE severity='CRITICAL'")
    if item_critical or lld_critical or lld_rule_critical:
        return {"level": "CRITICAL", "label": "Ajustes críticos encontrados", "detail": "Existem regressões que devem ser revisadas antes de encerrar a migração."}
    if item_high:
        return {"level": "HIGH", "label": "Migração requer ajustes", "detail": "Existem itens com regressão de alta severidade."}
    warnings = _scalar(conn, "SELECT COUNT(*) FROM anomalies WHERE severity='WARNING'") + _scalar(conn, "SELECT COUNT(*) FROM lld_summary WHERE severity='WARNING' AND category<>'OK'")
    if warnings:
        return {"level": "WARNING", "label": "Migração com alertas", "detail": "Não há criticidade detectada, mas existem pontos para revisão."}
    return {"level": "OK", "label": "Sem regressões relevantes", "detail": "Nenhuma regressão relevante foi encontrada pelos critérios atuais."}


def api_overview(db_path: Path) -> dict[str, Any]:
    with _conn(db_path) as conn:
        meta = _metadata(conn)
        summary = meta.get("summary", {}) if isinstance(meta.get("summary"), dict) else {}
        return {
            "status": _status(conn),
            "summary": summary,
            "pending_delete": _scalar(conn, "SELECT COALESCE(SUM(pending_delete_count),0) FROM lld_summary"),
            "templates_impacted": _scalar(conn, "SELECT COUNT(*) FROM template_summary"),
            "ignored_disabled_hosts": meta.get("ignored_current_disabled_hosts", 0),
            "interface_failure_hosts": _scalar(conn, "SELECT COUNT(*) FROM host_interface_failures"),
            "fetch_recovered": meta.get("current_fetch_recovered_by_presence", 0),
            "fetch_unresolved": meta.get("current_fetch_unresolved_existing_items", 0),
            "created_at_utc": meta.get("created_at_utc"),
            "current_dbversion": meta.get("current_dbversion"),
            "baseline_metadata": meta.get("baseline_metadata"),
        }


def api_charts(db_path: Path) -> dict[str, Any]:
    with _conn(db_path) as conn:
        categories = _rows(conn.execute("SELECT category label,COUNT(*) value FROM anomalies GROUP BY category ORDER BY value DESC"))
        hosts = _rows(conn.execute("""
            SELECT COALESCE(NULLIF(host_name,''),host,'(sem host)') label, COUNT(*) value,
                   SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END) critical,
                   SUM(CASE WHEN severity='HIGH' THEN 1 ELSE 0 END) high
            FROM anomalies GROUP BY hostid,host,host_name ORDER BY value DESC LIMIT 15
        """))
        lld = _rows(conn.execute("SELECT category label,COUNT(*) value FROM lld_summary WHERE category<>'OK' GROUP BY category ORDER BY value DESC"))
        reasons = _rows(conn.execute("SELECT reason label,COUNT(*) value FROM lld_child_anomalies GROUP BY reason ORDER BY value DESC"))
        errors = _rows(conn.execute("""
            SELECT CASE WHEN TRIM(COALESCE(current_error,''))='' THEN '(sem mensagem)' ELSE current_error END label,
                   COUNT(*) value
            FROM anomalies
            GROUP BY CASE WHEN TRIM(COALESCE(current_error,''))='' THEN '(sem mensagem)' ELSE current_error END
            ORDER BY value DESC LIMIT 10
        """))
        templates = _rows(conn.execute("""
            SELECT template_name label,impact_count value,critical_count critical,rank,template_hostid,
                   item_regressions,lld_lost_children,hosts_affected
            FROM template_summary ORDER BY rank LIMIT 20
        """))
        return {"categories": categories, "hosts": hosts, "lld": lld, "lld_reasons": reasons, "errors": errors, "templates": templates}


def _add_column_filters(params: dict[str, list[str]], allowed: dict[str, str], clauses: list[str], args: list[Any], alias: str = "") -> None:
    for key, expr in allowed.items():
        value = (params.get(f"f_{key}") or [""])[0].strip()
        if not value:
            continue
        field = f"{alias}.{expr}" if alias and expr.replace("_", "").isalnum() else expr
        clauses.append(f"LOWER(CAST({field} AS TEXT)) LIKE LOWER(?)")
        args.append(f"%{value}%")


def _where(params: dict[str, list[str]], table: str, column_filters: dict[str, str]) -> tuple[str, list[Any]]:
    clauses: list[str] = []
    args: list[Any] = []
    sev = (params.get("severity") or [""])[0].strip().upper()
    cat = (params.get("category") or [""])[0].strip()
    host = (params.get("host") or [""])[0].strip()
    q = (params.get("q") or [""])[0].strip()
    template = (params.get("template") or [""])[0].strip()
    if sev:
        clauses.append("severity=?")
        args.append(sev)
    if cat:
        clauses.append("category=?")
        args.append(cat)
    if host:
        clauses.append("CAST(hostid AS TEXT)=?")
        args.append(host)
    if template:
        clauses.append("CAST(base_template_hostid AS TEXT)=?")
        args.append(template)
    if q:
        like = f"%{q}%"
        if table == "anomalies":
            clauses.append("(host LIKE ? OR host_name LIKE ? OR item_name LIKE ? OR key_ LIKE ? OR current_key_ LIKE ? OR CAST(itemid AS TEXT) LIKE ? OR current_error LIKE ?)")
            args.extend([like] * 7)
        elif table == "lld_summary":
            clauses.append("(host LIKE ? OR host_name LIKE ? OR rule_name LIKE ? OR rule_key LIKE ? OR CAST(ruleid AS TEXT) LIKE ?)")
            args.extend([like] * 5)
        elif table == "lld_rule_anomalies":
            clauses.append("(host LIKE ? OR host_name LIKE ? OR rule_name LIKE ? OR key_ LIKE ? OR CAST(itemid AS TEXT) LIKE ? OR current_error LIKE ?)")
            args.extend([like] * 6)
    _add_column_filters(params, column_filters, clauses, args)
    return (" WHERE " + " AND ".join(clauses)) if clauses else "", args


def _paged(conn: sqlite3.Connection, table: str, columns: str, params: dict[str, list[str]], sorts: dict[str, str], filters: dict[str, str], default_sort: str, extra_clause: str | None = None) -> dict[str, Any]:
    page = max(1, int((params.get("page") or ["1"])[0] or 1))
    page_size = min(250, max(10, int((params.get("page_size") or ["50"])[0] or 50)))
    sort = (params.get("sort") or [default_sort])[0]
    direction = "ASC" if (params.get("dir") or ["desc"])[0].lower() == "asc" else "DESC"
    order = sorts.get(sort, sorts[default_sort])
    where, args = _where(params, table, filters)
    if extra_clause:
        where = (where + " AND " if where else " WHERE ") + extra_clause
    total = _scalar(conn, f"SELECT COUNT(*) FROM {table}{where}", tuple(args))
    sql = f"SELECT {columns} FROM {table}{where} ORDER BY {order} {direction}, rowid DESC LIMIT ? OFFSET ?"
    rows = _rows(conn.execute(sql, tuple(args + [page_size, (page - 1) * page_size])))
    return {"rows": rows, "total": total, "page": page, "page_size": page_size, "pages": max(1, (int(total) + page_size - 1) // page_size), "sort": sort, "dir": direction.lower()}


def api_items(db_path: Path, params: dict[str, list[str]]) -> dict[str, Any]:
    cols = "itemid,hostid,host,host_name,item_name,key_,category,severity,current_error,current_interface_error,master_itemid,master_anomaly_itemid,master_anomaly_category,dependent_affected_count,changed_fields,current_proxy_ref,baseline_proxy_ref,direct_template_hostid,direct_template_name,base_template_hostid,base_template_name,template_depth,baseline_item_type,current_item_type,current_item_name,current_key_,current_hostid,current_host,current_host_name"
    with _conn(db_path) as conn:
        return _paged(conn, "anomalies", cols, params, ITEM_SORTS, ITEM_FILTERS, "severity")


def api_lld(db_path: Path, params: dict[str, list[str]]) -> dict[str, Any]:
    cols = "group_id,ruleid,prototypeid,hostid,host,host_name,rule_name,rule_key,baseline_count,current_present_count,lost_count,loss_pct,baseline_operational_count,current_operational_count,operational_lost_count,operational_loss_pct,missing_count,metadata_missing_count,not_discovered_count,pending_delete_count,disabled_count,pending_disable_count,category,severity,direct_template_hostid,direct_template_name,base_template_hostid,base_template_name,template_depth"
    with _conn(db_path) as conn:
        return _paged(conn, "lld_summary", cols, params, LLD_SORTS, LLD_FILTERS, "severity")


def api_lld_rules(db_path: Path, params: dict[str, list[str]]) -> dict[str, Any]:
    cols = "itemid,hostid,host,host_name,rule_name,key_,category,severity,current_error,changed_fields,direct_template_hostid,direct_template_name,base_template_hostid,base_template_name,template_depth"
    with _conn(db_path) as conn:
        return _paged(conn, "lld_rule_anomalies", cols, params, LLD_RULE_SORTS, LLD_RULE_FILTERS, "severity")


def _filter_subquery(params: dict[str, list[str]], filters: dict[str, str], q_fields: list[str]) -> tuple[str, list[Any]]:
    clauses: list[str] = []
    args: list[Any] = []
    q = (params.get("q") or [""])[0].strip()
    if q:
        like = f"%{q}%"
        clauses.append("(" + " OR ".join(f"CAST({f} AS TEXT) LIKE ?" for f in q_fields) + ")")
        args.extend([like] * len(q_fields))
    _add_column_filters(params, filters, clauses, args)
    return (" WHERE " + " AND ".join(clauses)) if clauses else "", args


def api_hosts(db_path: Path, params: dict[str, list[str]]) -> dict[str, Any]:
    page = max(1, int((params.get("page") or ["1"])[0] or 1))
    page_size = min(250, max(10, int((params.get("page_size") or ["50"])[0] or 50)))
    direction = "ASC" if (params.get("dir") or ["desc"])[0].lower() == "asc" else "DESC"
    sort = (params.get("sort") or ["anomaly_count"])[0]
    order = HOST_SORTS.get(sort, HOST_SORTS["anomaly_count"])
    base = """
        SELECT hostid,host,COALESCE(NULLIF(host_name,''),host) host_name,COUNT(*) anomaly_count,
               SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END) critical_count,
               SUM(CASE WHEN severity='HIGH' THEN 1 ELSE 0 END) high_count,
               SUM(CASE WHEN severity='WARNING' THEN 1 ELSE 0 END) warning_count,
               COUNT(DISTINCT category) category_count,
               COALESCE(SUM(dependent_affected_count),0) dependent_affected_count
        FROM anomalies GROUP BY hostid,host,host_name
    """
    where, args = _filter_subquery(params, HOST_FILTERS, ["host", "host_name", "hostid"])
    with _conn(db_path) as conn:
        total = _scalar(conn, f"SELECT COUNT(*) FROM ({base}) x{where}", tuple(args))
        rows = _rows(conn.execute(f"SELECT * FROM ({base}) x{where} ORDER BY {order} {direction}, host_name ASC LIMIT ? OFFSET ?", tuple(args + [page_size, (page - 1) * page_size])))
        return {"rows": rows, "total": total, "page": page, "page_size": page_size, "pages": max(1, (int(total) + page_size - 1) // page_size), "sort": sort, "dir": direction.lower()}


def api_interface_hosts(db_path: Path, params: dict[str, list[str]]) -> dict[str, Any]:
    page = max(1, int((params.get("page") or ["1"])[0] or 1))
    page_size = min(250, max(10, int((params.get("page_size") or ["50"])[0] or 50)))
    direction = "ASC" if (params.get("dir") or ["asc"])[0].lower() == "asc" else "DESC"
    sort = (params.get("sort") or ["host_name"])[0]
    order = INTERFACE_HOST_SORTS.get(sort, INTERFACE_HOST_SORTS["host_name"])
    base = """
        SELECT
            hf.hostid, hf.host, COALESCE(NULLIF(hf.host_name,''),hf.host) host_name, hf.proxy_ref,
            hf.interface_count, hf.failing_interface_count,
            i.interfaceid, i.interface_type, i.interface_main, i.interface_useip,
            i.interface_ip, i.interface_dns, i.interface_port, i.interface_available, i.interface_error,
            CASE
                WHEN COALESCE(i.interface_useip,1)=1 THEN COALESCE(NULLIF(i.interface_ip,''),'(sem IP)')
                ELSE COALESCE(NULLIF(i.interface_dns,''),'(sem DNS)')
            END || CASE WHEN COALESCE(i.interface_port,'')<>'' THEN ':' || i.interface_port ELSE '' END AS endpoint
        FROM host_interface_failures hf
        JOIN current_host_interfaces i ON i.hostid=hf.hostid
        WHERE i.is_failure=1
    """
    where, args = _filter_subquery(
        params, INTERFACE_HOST_FILTERS,
        ["host", "host_name", "hostid", "interfaceid", "endpoint", "interface_error", "proxy_ref"]
    )
    with _conn(db_path) as conn:
        total = _scalar(conn, f"SELECT COUNT(*) FROM ({base}) x{where}", tuple(args))
        host_total = _scalar(conn, "SELECT COUNT(*) FROM host_interface_failures")
        rows = _rows(conn.execute(
            f"SELECT * FROM ({base}) x{where} ORDER BY {order} {direction}, host_name ASC, interfaceid ASC LIMIT ? OFFSET ?",
            tuple(args + [page_size, (page - 1) * page_size])
        ))
        return {
            "rows": rows, "total": total, "host_total": host_total, "page": page, "page_size": page_size,
            "pages": max(1, (int(total) + page_size - 1) // page_size), "sort": sort, "dir": direction.lower()
        }


def api_templates(db_path: Path, params: dict[str, list[str]]) -> dict[str, Any]:
    page = max(1, int((params.get("page") or ["1"])[0] or 1))
    page_size = min(250, max(10, int((params.get("page_size") or ["50"])[0] or 50)))
    direction = "ASC" if (params.get("dir") or ["asc"])[0].lower() == "asc" else "DESC"
    sort = (params.get("sort") or ["rank"])[0]
    order = TEMPLATE_SORTS.get(sort, TEMPLATE_SORTS["rank"])
    where, args = _filter_subquery(params, TEMPLATE_FILTERS, ["template_name", "template_host", "template_hostid"])
    with _conn(db_path) as conn:
        total = _scalar(conn, f"SELECT COUNT(*) FROM template_summary{where}", tuple(args))
        rows = _rows(conn.execute(f"""
            SELECT rank,template_hostid,template_host,template_name,priority_score,impact_count,hosts_affected,
                   item_regressions,lld_rule_regressions,lld_groups_with_loss,lld_total_loss,lld_lost_children,
                   lld_pending_delete,dependent_affected,critical_count,high_count,warning_count
            FROM template_summary{where}
            ORDER BY {order} {direction}, rank ASC LIMIT ? OFFSET ?
        """, tuple(args + [page_size, (page - 1) * page_size])))
        return {"rows": rows, "total": total, "page": page, "page_size": page_size, "pages": max(1, (int(total) + page_size - 1) // page_size), "sort": sort, "dir": direction.lower()}


def api_roots(db_path: Path, params: dict[str, list[str]]) -> dict[str, Any]:
    cols = "itemid,hostid,host,host_name,item_name,key_,category,severity,current_error,dependent_affected_count,changed_fields,base_template_hostid,base_template_name,baseline_item_type,current_item_type,current_key_"
    with _conn(db_path) as conn:
        return _paged(conn, "anomalies", cols, params, ROOT_SORTS, ROOT_FILTERS, "dependent_affected_count", "dependent_affected_count>0")


def _top_errors(conn: sqlite3.Connection, category: str | None = None, limit: int = 5) -> list[dict[str, Any]]:
    where = "WHERE TRIM(COALESCE(current_error,''))<>''"
    args: list[Any] = []
    if category:
        where += " AND category=?"
        args.append(category)
    return _rows(conn.execute(f"SELECT current_error error,COUNT(*) count FROM anomalies {where} GROUP BY current_error ORDER BY count DESC LIMIT ?", tuple(args + [limit])))


def api_recommendations(db_path: Path) -> dict[str, Any]:
    recs: list[dict[str, Any]] = []
    with _conn(db_path) as conn:
        def add(priority: str, code: str, title: str, count: int, why: str, action: str, evidence: Any = None, target: str | None = None) -> None:
            if count:
                recs.append({"priority": priority, "code": code, "title": title, "count": int(count), "why": why, "action": action, "evidence": evidence, "target": target})

        n = _scalar(conn, "SELECT COUNT(*) FROM lld_summary WHERE category='LLD_TOTAL_LOSS'")
        add("P0", "LLD_TOTAL_LOSS", "Restaurar discoveries com perda total", n,
            "Uma regra/prototype que possuía filhos válidos no Zabbix 6 ficou sem nenhum filho efetivamente presente no 7.",
            "Valide primeiro a própria regra LLD, macros, filtros, credenciais/interface e preprocessing.",
            _rows(conn.execute("SELECT ruleid,host,rule_name,baseline_count,lost_count,pending_delete_count FROM lld_summary WHERE category='LLD_TOTAL_LOSS' ORDER BY baseline_count DESC LIMIT 5")), "lld")

        n = _scalar(conn, "SELECT COUNT(*) FROM lld_rule_anomalies WHERE category IN ('LLD_NOT_SUPPORTED','LLD_MISSING','LLD_HOST_MISSING')")
        add("P0", "LLD_RULE_BROKEN", "Corrigir regras LLD quebradas", n,
            "A própria regra de discovery estava saudável no baseline e agora está ausente ou unsupported.",
            "Corrija a regra LLD antes de atuar nos filhos.",
            _rows(conn.execute("SELECT itemid,host,rule_name,category,current_error FROM lld_rule_anomalies WHERE category IN ('LLD_NOT_SUPPORTED','LLD_MISSING','LLD_HOST_MISSING') LIMIT 5")), "lld-rules")

        n = _scalar(conn, "SELECT COALESCE(SUM(pending_delete_count),0) FROM lld_summary")
        add("P0", "PENDING_DELETE", "Revisar itens LLD marcados para deleção", n,
            "Esses filhos ainda podem existir fisicamente no banco, mas já estão marcados para remoção.",
            "Confirme se a perda é esperada e corrija a causa do discovery antes do prazo de remoção.", None, "lld")

        roots = _scalar(conn, "SELECT COUNT(*) FROM anomalies WHERE dependent_affected_count>0")
        affected = _scalar(conn, "SELECT COALESCE(SUM(dependent_affected_count),0) FROM anomalies WHERE dependent_affected_count>0")
        if roots:
            recs.append({"priority": "P0" if affected >= 100 else "P1", "code": "MASTER_ROOT_CAUSE", "title": "Corrigir master items antes dos dependentes", "count": int(roots), "why": f"{roots} master item(ns) concentram {affected} dependente(s) afetado(s).", "action": "Trate o master como causa raiz e reavalie os dependentes após normalizá-lo.", "evidence": _rows(conn.execute("SELECT itemid,host,item_name,category,current_error,dependent_affected_count FROM anomalies WHERE dependent_affected_count>0 ORDER BY dependent_affected_count DESC LIMIT 8")), "target": "roots"})

        n = _scalar(conn, "SELECT COUNT(*) FROM template_summary")
        add("P1", "TEMPLATE_FOCUS", "Atacar regressões por template base", n,
            "Corrigir um template base pode normalizar muitos hosts e objetos de uma vez.",
            "Comece pelo Top 20 e valide em poucos hosts antes de propagar/retestar.",
            _rows(conn.execute("SELECT rank,template_hostid,template_name,impact_count,hosts_affected,item_regressions,lld_lost_children,critical_count,high_count FROM template_summary ORDER BY rank LIMIT 8")), "templates")

        n = _scalar(conn, "SELECT COUNT(*) FROM anomalies WHERE category='ITEM_NOT_SUPPORTED'")
        add("P1", "ITEM_NOT_SUPPORTED", "Resolver itens que viraram Not supported", n,
            "Os itens estavam normais no Zabbix 6 e estão unsupported no 7.",
            "Agrupe pela mensagem de erro do próprio item e corrija por causa comum.", _top_errors(conn, "ITEM_NOT_SUPPORTED", 8), "items")

        n = _scalar(conn, "SELECT COUNT(*) FROM host_interface_failures")
        add("P1", "INTERFACE_FAILURE", "Corrigir hosts com todas as interfaces em erro", n,
            "Esses hosts foram retirados das regressões de itens, LLD, templates e causas raiz porque nenhuma interface atual está sem erro.",
            "Trate primeiro conectividade, credenciais, proxy e disponibilidade da interface. Depois execute uma nova comparação para avaliar os objetos do host.",
            _rows(conn.execute("SELECT hostid,host,host_name,interface_count,errors_summary FROM host_interface_failures ORDER BY host_name LIMIT 8")),
            "interface-hosts")

        n = _scalar(conn, "SELECT COUNT(*) FROM anomalies WHERE category='ITEM_MISSING'")
        add("P1", "ITEM_MISSING", "Investigar somente IDs realmente ausentes em items", n,
            "Na v0.4, ITEM_MISSING só pode ocorrer quando o itemid não existe na tabela items do Zabbix 7.",
            "Confirme exclusão planejada ou falha de migração/importação.", None, "items")

        n = _scalar(conn, "SELECT COUNT(*) FROM anomalies WHERE category='ITEM_DISABLED'")
        add("P1", "ITEM_DISABLED", "Revisar itens desabilitados", n,
            "Itens habilitados no baseline aparecem desabilitados no ambiente novo, em hosts que continuam monitorados.",
            "Confirme overrides/prototypes e se a mudança foi intencional.", None, "items")

        n = _scalar(conn, "SELECT COUNT(*) FROM anomalies WHERE COALESCE(baseline_proxy_ref,-1)<>COALESCE(current_proxy_ref,-1)")
        add("P2", "PROXY_CHANGED", "Validar mudanças de proxy", n,
            "Há regressões em hosts cuja referência de proxy difere do baseline.",
            "Confirme se o novo proxy está ativo, compatível e recebendo configuração.", None, "hosts")

        n = _scalar(conn, "SELECT COUNT(*) FROM anomalies WHERE changed_fields<>''")
        fields: Counter[str] = Counter()
        for row in conn.execute("SELECT changed_fields FROM anomalies WHERE changed_fields<>''"):
            for field in (row[0] or "").split(","):
                if field:
                    fields[field] += 1
        add("P2", "STRUCTURAL_DIFF", "Revisar diferenças estruturais", n,
            "Há itens com regressão cujo cadastro mudou entre 6 e 7.",
            "Use as diferenças como pista de causa raiz, sobretudo key_, type, interfaceid e master_itemid.", [{"field": k, "count": v} for k, v in fields.most_common(10)], "items")

    recs.sort(key=lambda x: ({"P0": 0, "P1": 1, "P2": 2}.get(x["priority"], 9), -x["count"]))
    return {"rows": recs, "count": len(recs)}


def api_filters(db_path: Path) -> dict[str, Any]:
    with _conn(db_path) as conn:
        return {
            "item_categories": [r[0] for r in conn.execute("SELECT DISTINCT category FROM anomalies ORDER BY category")],
            "lld_categories": [r[0] for r in conn.execute("SELECT DISTINCT category FROM lld_summary WHERE category<>'OK' ORDER BY category")],
            "lld_rule_categories": [r[0] for r in conn.execute("SELECT DISTINCT category FROM lld_rule_anomalies ORDER BY category")],
            "templates": _rows(conn.execute("SELECT template_hostid,template_host,template_name,rank FROM template_summary ORDER BY rank LIMIT 5000")),
        }


def _json_bytes(data: Any) -> bytes:
    return json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


class DashboardHandler(BaseHTTPRequestHandler):
    db_path: Path
    static_dir: Path

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"[web] {self.address_string()} - {fmt % args}")

    def _send_json(self, data: Any, status: int = 200) -> None:
        body = _json_bytes(data)
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path: Path) -> None:
        if not path.exists() or not path.is_file():
            self.send_error(404)
            return
        body = path.read_bytes()
        mime = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-Type", mime + ("; charset=utf-8" if mime.startswith("text/") or mime in ("application/javascript", "application/json") else ""))
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        try:
            routes = {
                "/api/overview": lambda: api_overview(self.db_path),
                "/api/charts": lambda: api_charts(self.db_path),
                "/api/items": lambda: api_items(self.db_path, params),
                "/api/lld": lambda: api_lld(self.db_path, params),
                "/api/lld-rules": lambda: api_lld_rules(self.db_path, params),
                "/api/hosts": lambda: api_hosts(self.db_path, params),
                "/api/interface-hosts": lambda: api_interface_hosts(self.db_path, params),
                "/api/templates": lambda: api_templates(self.db_path, params),
                "/api/roots": lambda: api_roots(self.db_path, params),
                "/api/recommendations": lambda: api_recommendations(self.db_path),
                "/api/filters": lambda: api_filters(self.db_path),
                "/api/health": lambda: {"status": "ok", "database": self.db_path.name},
            }
            if parsed.path in routes:
                return self._send_json(routes[parsed.path]())
            if parsed.path in ("/", "/index.html"):
                return self._send_file(self.static_dir / "index.html")
            rel = parsed.path.lstrip("/")
            candidate = (self.static_dir / rel).resolve()
            if self.static_dir.resolve() not in candidate.parents:
                return self.send_error(403)
            return self._send_file(candidate)
        except (ValueError, sqlite3.Error) as exc:
            return self._send_json({"error": str(exc)}, status=400)
        except Exception as exc:
            return self._send_json({"error": f"Falha interna: {exc}"}, status=500)


def serve(results_db: str | Path, host: str = "127.0.0.1", port: int = 8088) -> None:
    db_path = Path(results_db).expanduser().resolve()
    if db_path.is_dir():
        db_path = db_path / "comparison_results.sqlite"
    if not db_path.exists():
        raise FileNotFoundError(f"Banco de comparação não encontrado: {db_path}")
    with _conn(db_path) as conn:
        required = {"metadata", "anomalies", "lld_summary", "lld_rule_anomalies", "host_summary", "template_summary", "current_host_interfaces", "host_interface_failures"}
        existing = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        missing = required - existing
        if missing:
            raise RuntimeError("Arquivo incompleto para o frontend: " + ", ".join(sorted(missing)))
        anomaly_cols = {r[1] for r in conn.execute("PRAGMA table_info(anomalies)")}
        needed = {"baseline_item_type", "current_item_type", "current_key_", "current_item_name"}
        if not needed.issubset(anomaly_cols):
            raise RuntimeError("Este comparison_results.sqlite foi gerado por uma versão anterior. Reexecute apenas o comando compare com a v0.4.1 usando o mesmo snapshot do Zabbix 6; não é necessário refazer o snapshot.")

    static_dir = Path(__file__).with_name("webapp")
    handler = type("BoundDashboardHandler", (DashboardHandler,), {"db_path": db_path, "static_dir": static_dir})
    server = ThreadingHTTPServer((host, port), handler)
    print(f"Dashboard Zabbix Migration Checker: http://{host}:{port}")
    print(f"Resultados: {db_path}")
    if host not in ("127.0.0.1", "localhost", "::1"):
        print("ATENÇÃO: o dashboard não possui autenticação própria. Proteja-o com firewall/reverse proxy se estiver acessível em rede.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def add_serve_parser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("serve", help="Inicia o frontend web sobre um comparison_results.sqlite")
    p.add_argument("--results", required=True, help="Caminho para comparison_results.sqlite ou para o diretório do relatório")
    p.add_argument("--host", default="127.0.0.1", help="IP de bind (default: 127.0.0.1)")
    p.add_argument("--port", type=int, default=8088, help="Porta HTTP (default: 8088)")
    p.set_defaults(func=lambda args: (serve(args.results, args.host, args.port) or 0))
