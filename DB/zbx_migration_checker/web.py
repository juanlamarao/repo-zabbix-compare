from __future__ import annotations

import argparse
import json
import mimetypes
import sqlite3
import urllib.parse
from collections import Counter
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "WARNING": 2, "OK": 1}

ITEM_SORTS = {
    "severity": "CASE severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'WARNING' THEN 2 ELSE 1 END",
    "host": "host",
    "itemid": "itemid",
    "category": "category",
    "item_name": "item_name",
    "dependent_affected_count": "dependent_affected_count",
}
LLD_SORTS = {
    "severity": "CASE severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'WARNING' THEN 2 ELSE 1 END",
    "host": "host",
    "ruleid": "ruleid",
    "loss_pct": "loss_pct",
    "operational_loss_pct": "operational_loss_pct",
    "lost_count": "lost_count",
    "baseline_count": "baseline_count",
}
LLD_RULE_SORTS = {
    "severity": "CASE severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'WARNING' THEN 2 ELSE 1 END",
    "host": "host",
    "itemid": "itemid",
    "category": "category",
    "rule_name": "rule_name",
}
HOST_SORTS = {
    "anomaly_count": "anomaly_count",
    "host": "host",
    "critical": "critical_count",
    "high": "high_count",
}
TEMPLATE_SORTS = {
    "rank": "rank",
    "priority_score": "priority_score",
    "impact_count": "impact_count",
    "template_name": "template_name",
    "hosts_affected": "hosts_affected",
    "item_regressions": "item_regressions",
    "critical_count": "critical_count",
    "lld_lost_children": "lld_lost_children",
}


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
        severity = {r["severity"]: r["n"] for r in conn.execute("SELECT severity,COUNT(*) n FROM anomalies GROUP BY severity")}
        lld_severity = {r["severity"]: r["n"] for r in conn.execute("SELECT severity,COUNT(*) n FROM lld_summary WHERE category<>'OK' GROUP BY severity")}
        roots = _scalar(conn, "SELECT COUNT(*) FROM anomalies WHERE dependent_affected_count>0")
        dependents = _scalar(conn, "SELECT COALESCE(SUM(dependent_affected_count),0) FROM anomalies WHERE dependent_affected_count>0")
        pending_delete = _scalar(conn, "SELECT COALESCE(SUM(pending_delete_count),0) FROM lld_summary")
        return {
            "status": _status(conn),
            "summary": summary,
            "severity": severity,
            "lld_severity": lld_severity,
            "root_causes": roots,
            "dependent_affected": dependents,
            "pending_delete": pending_delete,
            "templates_impacted": _scalar(conn, "SELECT COUNT(*) FROM template_summary"),
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


def _where(params: dict[str, list[str]], table: str) -> tuple[str, list[Any]]:
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
            clauses.append("(host LIKE ? OR host_name LIKE ? OR item_name LIKE ? OR key_ LIKE ? OR CAST(itemid AS TEXT) LIKE ? OR current_error LIKE ?)")
            args.extend([like] * 6)
        elif table == "lld_summary":
            clauses.append("(host LIKE ? OR host_name LIKE ? OR rule_name LIKE ? OR rule_key LIKE ? OR CAST(ruleid AS TEXT) LIKE ?)")
            args.extend([like] * 5)
        elif table == "lld_rule_anomalies":
            clauses.append("(host LIKE ? OR host_name LIKE ? OR rule_name LIKE ? OR key_ LIKE ? OR CAST(itemid AS TEXT) LIKE ? OR current_error LIKE ?)")
            args.extend([like] * 6)
    return (" WHERE " + " AND ".join(clauses)) if clauses else "", args


def _paged(conn: sqlite3.Connection, table: str, columns: str, params: dict[str, list[str]], sorts: dict[str, str], default_sort: str) -> dict[str, Any]:
    page = max(1, int((params.get("page") or ["1"])[0] or 1))
    page_size = min(250, max(10, int((params.get("page_size") or ["50"])[0] or 50)))
    sort = (params.get("sort") or [default_sort])[0]
    direction = "ASC" if (params.get("dir") or ["desc"])[0].lower() == "asc" else "DESC"
    order = sorts.get(sort, sorts[default_sort])
    where, args = _where(params, table)
    total = _scalar(conn, f"SELECT COUNT(*) FROM {table}{where}", tuple(args))
    sql = f"SELECT {columns} FROM {table}{where} ORDER BY {order} {direction}, rowid DESC LIMIT ? OFFSET ?"
    rows = _rows(conn.execute(sql, tuple(args + [page_size, (page - 1) * page_size])))
    return {"rows": rows, "total": total, "page": page, "page_size": page_size, "pages": max(1, (int(total) + page_size - 1) // page_size)}


def api_items(db_path: Path, params: dict[str, list[str]]) -> dict[str, Any]:
    with _conn(db_path) as conn:
        return _paged(conn, "anomalies", "itemid,hostid,host,host_name,item_name,key_,category,severity,current_error,current_interface_error,master_itemid,master_anomaly_itemid,master_anomaly_category,dependent_affected_count,changed_fields,current_proxy_ref,baseline_proxy_ref,direct_template_hostid,direct_template_name,base_template_hostid,base_template_name,template_depth", params, ITEM_SORTS, "severity")


def api_lld(db_path: Path, params: dict[str, list[str]]) -> dict[str, Any]:
    with _conn(db_path) as conn:
        return _paged(conn, "lld_summary", "group_id,ruleid,prototypeid,hostid,host,host_name,rule_name,rule_key,baseline_count,current_present_count,lost_count,loss_pct,baseline_operational_count,current_operational_count,operational_lost_count,operational_loss_pct,missing_count,metadata_missing_count,not_discovered_count,pending_delete_count,disabled_count,pending_disable_count,category,severity,direct_template_hostid,direct_template_name,base_template_hostid,base_template_name,template_depth", params, LLD_SORTS, "severity")


def api_lld_rules(db_path: Path, params: dict[str, list[str]]) -> dict[str, Any]:
    with _conn(db_path) as conn:
        return _paged(conn, "lld_rule_anomalies", "itemid,hostid,host,host_name,rule_name,key_,category,severity,current_error,changed_fields,direct_template_hostid,direct_template_name,base_template_hostid,base_template_name,template_depth", params, LLD_RULE_SORTS, "severity")


def api_hosts(db_path: Path, params: dict[str, list[str]]) -> dict[str, Any]:
    page = max(1, int((params.get("page") or ["1"])[0] or 1))
    page_size = min(250, max(10, int((params.get("page_size") or ["50"])[0] or 50)))
    q = (params.get("q") or [""])[0].strip()
    direction = "ASC" if (params.get("dir") or ["desc"])[0].lower() == "asc" else "DESC"
    sort = (params.get("sort") or ["anomaly_count"])[0]
    order = HOST_SORTS.get(sort, HOST_SORTS["anomaly_count"])
    with _conn(db_path) as conn:
        where = ""
        args: list[Any] = []
        if q:
            where = "WHERE host LIKE ? OR host_name LIKE ?"
            args = [f"%{q}%", f"%{q}%"]
        base = f"""
            SELECT hostid,host,host_name,COUNT(*) anomaly_count,
                   SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END) critical_count,
                   SUM(CASE WHEN severity='HIGH' THEN 1 ELSE 0 END) high_count,
                   SUM(CASE WHEN severity='WARNING' THEN 1 ELSE 0 END) warning_count,
                   COUNT(DISTINCT category) category_count,
                   COALESCE(SUM(dependent_affected_count),0) dependent_affected_count
            FROM anomalies {where}
            GROUP BY hostid,host,host_name
        """
        total = _scalar(conn, f"SELECT COUNT(*) FROM ({base}) x", tuple(args))
        rows = _rows(conn.execute(f"{base} ORDER BY {order} {direction}, host ASC LIMIT ? OFFSET ?", tuple(args + [page_size, (page - 1) * page_size])))
        return {"rows": rows, "total": total, "page": page, "page_size": page_size, "pages": max(1, (int(total) + page_size - 1) // page_size)}


def api_templates(db_path: Path, params: dict[str, list[str]]) -> dict[str, Any]:
    page = max(1, int((params.get("page") or ["1"])[0] or 1))
    page_size = min(250, max(10, int((params.get("page_size") or ["50"])[0] or 50)))
    q = (params.get("q") or [""])[0].strip()
    direction = "ASC" if (params.get("dir") or ["asc"])[0].lower() == "asc" else "DESC"
    sort = (params.get("sort") or ["rank"])[0]
    order = TEMPLATE_SORTS.get(sort, TEMPLATE_SORTS["rank"])
    with _conn(db_path) as conn:
        where = ""
        args: list[Any] = []
        if q:
            where = "WHERE template_name LIKE ? OR template_host LIKE ? OR CAST(template_hostid AS TEXT) LIKE ?"
            like = f"%{q}%"
            args = [like, like, like]
        total = _scalar(conn, f"SELECT COUNT(*) FROM template_summary {where}", tuple(args))
        rows = _rows(conn.execute(f"""
            SELECT rank,template_hostid,template_host,template_name,priority_score,impact_count,hosts_affected,
                   item_regressions,lld_rule_regressions,lld_groups_with_loss,lld_total_loss,lld_lost_children,
                   lld_pending_delete,dependent_affected,critical_count,high_count,warning_count
            FROM template_summary {where}
            ORDER BY {order} {direction}, rank ASC LIMIT ? OFFSET ?
        """, tuple(args + [page_size, (page - 1) * page_size])))
        return {"rows": rows, "total": total, "page": page, "page_size": page_size, "pages": max(1, (int(total) + page_size - 1) // page_size)}


def api_roots(db_path: Path) -> dict[str, Any]:
    with _conn(db_path) as conn:
        rows = _rows(conn.execute("""
            SELECT itemid,hostid,host,host_name,item_name,key_,category,severity,current_error,
                   dependent_affected_count,changed_fields,base_template_hostid,base_template_name
            FROM anomalies
            WHERE dependent_affected_count>0
            ORDER BY dependent_affected_count DESC,
                     CASE severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'WARNING' THEN 2 ELSE 1 END DESC
            LIMIT 200
        """))
        return {"rows": rows, "total": _scalar(conn, "SELECT COUNT(*) FROM anomalies WHERE dependent_affected_count>0")}


def _top_errors(conn: sqlite3.Connection, category: str | None = None, limit: int = 5) -> list[dict[str, Any]]:
    where = "WHERE TRIM(COALESCE(current_error,''))<>''"
    args: list[Any] = []
    if category:
        where += " AND category=?"
        args.append(category)
    return _rows(conn.execute(f"""
        SELECT current_error error,COUNT(*) count
        FROM anomalies {where}
        GROUP BY current_error ORDER BY count DESC LIMIT ?
    """, tuple(args + [limit])))


def api_recommendations(db_path: Path) -> dict[str, Any]:
    recs: list[dict[str, Any]] = []
    with _conn(db_path) as conn:
        def add(priority: str, code: str, title: str, count: int, why: str, action: str, evidence: Any = None, target: str | None = None) -> None:
            if count:
                recs.append({"priority": priority, "code": code, "title": title, "count": int(count), "why": why, "action": action, "evidence": evidence, "target": target})

        n = _scalar(conn, "SELECT COUNT(*) FROM lld_summary WHERE category='LLD_TOTAL_LOSS'")
        examples = _rows(conn.execute("SELECT ruleid,host,rule_name,baseline_count,lost_count,pending_delete_count FROM lld_summary WHERE category='LLD_TOTAL_LOSS' ORDER BY baseline_count DESC LIMIT 5"))
        add("P0", "LLD_TOTAL_LOSS", "Restaurar discoveries com perda total", n,
            "Uma regra/prototype que possuía filhos válidos no Zabbix 6 ficou sem nenhum filho efetivamente presente no 7.",
            "Priorize essas LLDs. Valide o estado da própria regra, macros, filtros, credenciais/interface e preprocessing. Se houver filhos com deleção agendada, corrija a causa do discovery antes do prazo de remoção.", examples, "lld")

        n = _scalar(conn, "SELECT COUNT(*) FROM lld_rule_anomalies WHERE category IN ('LLD_NOT_SUPPORTED','LLD_MISSING','LLD_HOST_MISSING')")
        examples = _rows(conn.execute("SELECT itemid,host,rule_name,category,current_error FROM lld_rule_anomalies WHERE category IN ('LLD_NOT_SUPPORTED','LLD_MISSING','LLD_HOST_MISSING') ORDER BY CASE severity WHEN 'CRITICAL' THEN 4 ELSE 1 END DESC LIMIT 5"))
        add("P0", "LLD_RULE_BROKEN", "Corrigir regras LLD quebradas", n,
            "A própria regra de discovery estava saudável no baseline e agora está ausente ou unsupported.",
            "Corrija primeiro a regra LLD e só depois os filhos. Use a mensagem de erro como evidência e confira diferenças de configuração registradas em changed_fields.", examples, "lld-rules")

        n = _scalar(conn, "SELECT COALESCE(SUM(pending_delete_count),0) FROM lld_summary")
        examples = _rows(conn.execute("SELECT ruleid,host,rule_name,pending_delete_count,lost_count FROM lld_summary WHERE pending_delete_count>0 ORDER BY pending_delete_count DESC LIMIT 5"))
        add("P0", "PENDING_DELETE", "Revisar itens LLD marcados para deleção", n,
            "Esses filhos ainda podem existir fisicamente no banco, mas já estão marcados para remoção pelo mecanismo LLD.",
            "Verifique se a perda é esperada. Quando não for, restaure o discovery e revise a política/lifetime de lost resources antes que os objetos sejam apagados.", examples, "lld")

        roots = _scalar(conn, "SELECT COUNT(*) FROM anomalies WHERE dependent_affected_count>0")
        affected = _scalar(conn, "SELECT COALESCE(SUM(dependent_affected_count),0) FROM anomalies WHERE dependent_affected_count>0")
        examples = _rows(conn.execute("SELECT itemid,host,item_name,category,current_error,dependent_affected_count FROM anomalies WHERE dependent_affected_count>0 ORDER BY dependent_affected_count DESC LIMIT 8"))
        if roots:
            recs.append({"priority": "P0" if affected >= 100 else "P1", "code": "MASTER_ROOT_CAUSE", "title": "Corrigir master items antes dos dependentes", "count": int(roots), "why": f"{roots} master item(ns) em regressão concentram {affected} dependente(s) também afetado(s).", "action": "Trate o master item como causa raiz. Após normalizá-lo, reavalie os dependentes antes de fazer alterações individuais.", "evidence": examples, "target": "roots"})

        n = _scalar(conn, "SELECT COUNT(*) FROM template_summary")
        examples = _rows(conn.execute("""
            SELECT rank,template_hostid,template_name,impact_count,hosts_affected,item_regressions,
                   lld_groups_with_loss,lld_lost_children,critical_count,high_count
            FROM template_summary ORDER BY rank LIMIT 8
        """))
        add("P1", "TEMPLATE_FOCUS", "Atacar regressões por template base", n,
            "As regressões foram correlacionadas com a origem de herança do item. Corrigir um template base pode normalizar muitos hosts e objetos de uma só vez.",
            "Comece pelos templates do Top 20, priorizando os que concentram CRITICAL, perda total de LLD e maior impacto. Corrija no template base, valide em poucos hosts e então propague/reteste.", examples, "templates")

        n = _scalar(conn, "SELECT COUNT(*) FROM anomalies WHERE category='ITEM_NOT_SUPPORTED'")
        add("P1", "ITEM_NOT_SUPPORTED", "Resolver itens que viraram Not supported", n,
            "Os itens estavam normais no Zabbix 6 e estão unsupported no 7.",
            "Agrupe pela mensagem de erro para corrigir por causa comum. Confira timeout, interface, credenciais, OID/key, preprocessing e master item; dê prioridade aos erros mais repetidos.", _top_errors(conn, "ITEM_NOT_SUPPORTED", 8), "items")

        n = _scalar(conn, "SELECT COUNT(*) FROM anomalies WHERE COALESCE(current_interface_error,'')<>'' OR current_interface_available=2")
        examples = _rows(conn.execute("SELECT host,host_name,COUNT(*) count,MAX(current_interface_error) interface_error FROM anomalies WHERE COALESCE(current_interface_error,'')<>'' OR current_interface_available=2 GROUP BY hostid,host,host_name ORDER BY count DESC LIMIT 8"))
        add("P1", "INTERFACE_FAILURE", "Corrigir falhas de interface antes dos itens", n,
            "Há regressões associadas a interfaces indisponíveis ou com mensagem de erro no ambiente novo.",
            "Valide conectividade, endereço/DNS, porta, credenciais SNMP/JMX/IPMI/agent e associação da interface. Corrija a interface/host primeiro e reavalie os itens afetados.", examples, "hosts")

        n = _scalar(conn, "SELECT COUNT(*) FROM anomalies WHERE category IN ('HOST_MISSING','HOST_DISABLED')")
        examples = _rows(conn.execute("SELECT host,host_name,category,COUNT(*) count FROM anomalies WHERE category IN ('HOST_MISSING','HOST_DISABLED') GROUP BY hostid,host,host_name,category ORDER BY count DESC LIMIT 8"))
        add("P1", "HOST_STATE", "Revisar hosts ausentes ou desabilitados", n,
            "Muitos erros de item podem ser consequência do estado do host em vez de problemas individuais de coleta.",
            "Compare o status do host entre os ambientes e confirme se a ausência/desabilitação foi planejada. Corrija no nível do host antes de atuar item a item.", examples, "hosts")

        n = _scalar(conn, "SELECT COUNT(*) FROM anomalies WHERE category='ITEM_MISSING'")
        examples = _rows(conn.execute("SELECT host,itemid,item_name,key_,changed_fields FROM anomalies WHERE category='ITEM_MISSING' ORDER BY host LIMIT 8"))
        add("P1", "ITEM_MISSING", "Investigar itens do baseline ausentes", n,
            "O item existia e estava saudável no Zabbix 6, mas o mesmo itemid não foi encontrado no 7.",
            "Confirme se houve exclusão intencional durante o upgrade/importação. Se não houve, restaure a configuração correspondente e investigue a origem da perda.", examples, "items")

        n = _scalar(conn, "SELECT COUNT(*) FROM anomalies WHERE category='ITEM_DISABLED'")
        add("P1", "ITEM_DISABLED", "Revisar itens desabilitados após a migração", n,
            "Itens habilitados e saudáveis no baseline aparecem desabilitados no novo ambiente.",
            "Confirme se a mudança foi intencional. Quando não for, reabilite pelo mecanismo correto (item, prototype ou LLD) e valide se não há regra de override desabilitando o objeto.", None, "items")

        n = _scalar(conn, "SELECT COUNT(*) FROM anomalies WHERE baseline_proxy_ref IS NOT current_proxy_ref AND COALESCE(baseline_proxy_ref,-1)<>COALESCE(current_proxy_ref,-1)")
        examples = _rows(conn.execute("SELECT host,host_name,baseline_proxy_ref,current_proxy_ref,COUNT(*) count FROM anomalies WHERE COALESCE(baseline_proxy_ref,-1)<>COALESCE(current_proxy_ref,-1) GROUP BY hostid,host,host_name,baseline_proxy_ref,current_proxy_ref ORDER BY count DESC LIMIT 8"))
        add("P2", "PROXY_CHANGED", "Validar mudanças de proxy nos hosts afetados", n,
            "Existem itens com regressão em que a referência de proxy difere do baseline.",
            "Se a mudança de proxy fazia parte do plano, confirme que o novo proxy está ativo, compatível e recebendo a configuração. Se não era esperada, revise a associação do host/proxy.", examples, "hosts")

        n = _scalar(conn, "SELECT COUNT(*) FROM anomalies WHERE changed_fields<>''")
        fields: Counter[str] = Counter()
        for row in conn.execute("SELECT changed_fields FROM anomalies WHERE changed_fields<>''"):
            for field in (row[0] or "").split(","):
                if field:
                    fields[field] += 1
        add("P2", "STRUCTURAL_DIFF", "Revisar diferenças estruturais nos itens que regrediram", n,
            "Há itens com regressão cujo cadastro mudou entre 6 e 7.",
            "Use as diferenças como pista de causa raiz. Priorize campos que aparecem em muitos itens e valide se foram alterados pelo upgrade/template/importação.", [{"field": k, "count": v} for k, v in fields.most_common(10)], "items")

        n = _scalar(conn, "SELECT COUNT(*) FROM anomalies WHERE category='RTDATA_MISSING'")
        add("P2", "RTDATA_MISSING", "Validar itens sem runtime data", n,
            "O comparador não encontrou estado runtime equivalente no novo ambiente para itens que estavam saudáveis no baseline.",
            "Valide se o server/proxy já processou esses itens, se a configuração foi carregada e se houve tempo suficiente para a primeira coleta após a migração.", None, "items")

        n = _scalar(conn, "SELECT COALESCE(SUM(pending_disable_count + disabled_count),0) FROM lld_summary")
        add("P2", "LLD_DISABLED_CHILDREN", "Revisar filhos LLD desabilitados", n,
            "Parte dos filhos do baseline deixou de estar operacional no Zabbix 7 mesmo permanecendo presente.",
            "Confirme overrides, política de lost resources e mudanças de prototype antes de reabilitar manualmente. Prefira corrigir a regra/prototype quando o padrão for massivo.", None, "lld")

    recs.sort(key=lambda x: ({"P0": 0, "P1": 1, "P2": 2}.get(x["priority"], 9), -x["count"]))
    return {"rows": recs, "count": len(recs)}


def api_filters(db_path: Path) -> dict[str, Any]:
    with _conn(db_path) as conn:
        return {
            "item_categories": [r[0] for r in conn.execute("SELECT DISTINCT category FROM anomalies ORDER BY category")],
            "lld_categories": [r[0] for r in conn.execute("SELECT DISTINCT category FROM lld_summary WHERE category<>'OK' ORDER BY category")],
            "lld_rule_categories": [r[0] for r in conn.execute("SELECT DISTINCT category FROM lld_rule_anomalies ORDER BY category")],
            "hosts": _rows(conn.execute("SELECT DISTINCT hostid,host,host_name FROM anomalies ORDER BY COALESCE(NULLIF(host_name,''),host) LIMIT 5000")),
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
            if parsed.path == "/api/overview":
                return self._send_json(api_overview(self.db_path))
            if parsed.path == "/api/charts":
                return self._send_json(api_charts(self.db_path))
            if parsed.path == "/api/items":
                return self._send_json(api_items(self.db_path, params))
            if parsed.path == "/api/lld":
                return self._send_json(api_lld(self.db_path, params))
            if parsed.path == "/api/lld-rules":
                return self._send_json(api_lld_rules(self.db_path, params))
            if parsed.path == "/api/hosts":
                return self._send_json(api_hosts(self.db_path, params))
            if parsed.path == "/api/templates":
                return self._send_json(api_templates(self.db_path, params))
            if parsed.path == "/api/roots":
                return self._send_json(api_roots(self.db_path))
            if parsed.path == "/api/recommendations":
                return self._send_json(api_recommendations(self.db_path))
            if parsed.path == "/api/filters":
                return self._send_json(api_filters(self.db_path))
            if parsed.path == "/api/health":
                return self._send_json({"status": "ok", "database": self.db_path.name})
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
        required = {"metadata", "anomalies", "lld_summary", "lld_rule_anomalies", "host_summary", "template_summary"}
        existing = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        missing = required - existing
        if missing:
            raise RuntimeError("Arquivo não está enriquecido para o frontend atual; tabelas ausentes: " + ", ".join(sorted(missing)) + ". Para resultados v0.2, execute o comando enrich-templates com o snapshot do Zabbix 6.")

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
