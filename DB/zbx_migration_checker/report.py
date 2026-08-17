from __future__ import annotations

import html
import json
import sqlite3
from pathlib import Path
from typing import Any

from .snapshot import open_sqlite


def _esc(value: Any) -> str:
    if value is None:
        return ""
    return html.escape(str(value))


def _badge(severity: str) -> str:
    return f'<span class="badge {html.escape(severity.lower())}">{html.escape(severity)}</span>'


def _table(headers: list[str], rows: list[list[Any]]) -> str:
    if not rows:
        return '<p class="muted">Nenhum registro.</p>'
    thead = "".join(f"<th>{_esc(h)}</th>" for h in headers)
    body_parts = []
    for row in rows:
        cells = []
        for idx, value in enumerate(row):
            if headers[idx].lower() == "severity":
                cells.append(f"<td>{_badge(str(value))}</td>")
            else:
                cells.append(f"<td>{_esc(value)}</td>")
        body_parts.append("<tr>" + "".join(cells) + "</tr>")
    return f'<div class="table-wrap"><table><thead><tr>{thead}</tr></thead><tbody>{"".join(body_parts)}</tbody></table></div>'


def generate_html(results_db: str | Path, output_path: str | Path, row_limit: int = 500) -> Path:
    db_path = Path(results_db)
    output = Path(output_path)
    conn = open_sqlite(db_path)
    try:
        metadata = {r["key"]: json.loads(r["value"]) for r in conn.execute("SELECT key,value FROM metadata")}
        summary = metadata.get("summary", {})
        thresholds = metadata.get("thresholds", {})
        baseline_meta = metadata.get("baseline_metadata", {})
        current_dbversion = metadata.get("current_dbversion", {})

        item_categories = [list(r) for r in conn.execute(
            "SELECT category,severity,COUNT(*) FROM anomalies GROUP BY category,severity ORDER BY COUNT(*) DESC"
        )]
        lld_rule_categories = [list(r) for r in conn.execute(
            "SELECT category,severity,COUNT(*) FROM lld_rule_anomalies GROUP BY category,severity ORDER BY COUNT(*) DESC"
        )]
        lld_loss = [list(r) for r in conn.execute(
            """
            SELECT severity,category,host,rule_name,ruleid,baseline_count,current_present_count,
                   ROUND(loss_pct,2),disabled_count,pending_disable_count
            FROM lld_summary WHERE category <> 'OK'
            ORDER BY CASE severity WHEN 'CRITICAL' THEN 3 WHEN 'HIGH' THEN 2 WHEN 'WARNING' THEN 1 ELSE 0 END DESC,
                     loss_pct DESC
            LIMIT ?
            """, (row_limit,)
        )]
        item_rows = [list(r) for r in conn.execute(
            """
            SELECT severity,category,host,itemid,item_name,key_,current_error,changed_fields,
                   master_anomaly_itemid,dependent_affected_count
            FROM anomalies
            ORDER BY CASE severity WHEN 'CRITICAL' THEN 3 WHEN 'HIGH' THEN 2 WHEN 'WARNING' THEN 1 ELSE 0 END DESC,
                     host,itemid
            LIMIT ?
            """, (row_limit,)
        )]
        lld_rule_rows = [list(r) for r in conn.execute(
            """
            SELECT severity,category,host,itemid,rule_name,key_,current_error,changed_fields
            FROM lld_rule_anomalies
            ORDER BY CASE severity WHEN 'CRITICAL' THEN 3 WHEN 'HIGH' THEN 2 WHEN 'WARNING' THEN 1 ELSE 0 END DESC,
                     host,itemid
            LIMIT ?
            """, (row_limit,)
        )]
        root_rows = [list(r) for r in conn.execute(
            """
            SELECT severity,host,itemid,item_name,key_,category,dependent_affected_count,current_error
            FROM anomalies
            WHERE dependent_affected_count > 0
            ORDER BY dependent_affected_count DESC
            LIMIT ?
            """, (row_limit,)
        )]
        host_rows = [list(r) for r in conn.execute(
            """
            SELECT host,host_name,SUM(anomaly_count) total
            FROM host_summary
            GROUP BY hostid,host,host_name
            ORDER BY total DESC
            LIMIT ?
            """, (row_limit,)
        )]
    finally:
        conn.close()

    cards = [
        ("Itens no baseline", summary.get("baseline_item_count", 0)),
        ("Itens saudáveis analisados", summary.get("baseline_healthy_items_analyzed", 0)),
        ("Regressões de itens", summary.get("item_regressions", 0)),
        ("LLD rules com regressão", summary.get("lld_rule_regressions", 0)),
        ("LLDs com perda relevante", summary.get("lld_groups_with_loss", 0)),
        ("LLDs com perda total", summary.get("lld_total_loss", 0)),
        ("Hosts impactados", summary.get("hosts_impacted", 0)),
    ]
    cards_html = "".join(
        f'<div class="card"><div class="card-label">{_esc(label)}</div><div class="card-value">{int(value):,}</div></div>'
        for label, value in cards
    )

    page = f"""<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Zabbix 6 → 7 - Relatório de regressão</title>
<style>
:root {{ color-scheme: light dark; --bg:#101419; --panel:#171d24; --border:#2b3440; --text:#e8edf2; --muted:#9aa7b4; }}
* {{ box-sizing:border-box; }}
body {{ margin:0; font-family:Inter,Segoe UI,Arial,sans-serif; background:var(--bg); color:var(--text); }}
main {{ max-width:1600px; margin:auto; padding:28px; }}
h1 {{ margin:0 0 6px; font-size:28px; }} h2 {{ margin-top:34px; }}
.muted {{ color:var(--muted); }}
.cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(190px,1fr)); gap:12px; margin:22px 0; }}
.card {{ background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:16px; }}
.card-label {{ color:var(--muted); font-size:13px; }} .card-value {{ font-size:28px; font-weight:700; margin-top:6px; }}
.info {{ background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:14px 16px; line-height:1.55; }}
.table-wrap {{ overflow:auto; border:1px solid var(--border); border-radius:10px; }}
table {{ width:100%; border-collapse:collapse; min-width:900px; background:var(--panel); }}
th,td {{ padding:9px 10px; border-bottom:1px solid var(--border); text-align:left; vertical-align:top; font-size:13px; }}
th {{ position:sticky; top:0; background:#202833; z-index:1; }}
.badge {{ display:inline-block; padding:2px 8px; border-radius:999px; font-weight:700; font-size:11px; border:1px solid currentColor; }}
.badge.critical {{ color:#ff6b6b; }} .badge.high {{ color:#ffb454; }} .badge.warning {{ color:#ffe066; }} .badge.ok {{ color:#69db7c; }}
a {{ color:#74c0fc; }} code {{ background:#202833; padding:2px 5px; border-radius:4px; }}
</style>
</head>
<body><main>
<h1>Zabbix 6 → 7 — Comparação de banco</h1>
<p class="muted">Fonte da verdade: snapshot do Zabbix 6. Itens existentes somente no Zabbix 7 não entram na análise de regressão.</p>
<div class="cards">{cards_html}</div>
<div class="info">
<strong>Baseline DB version:</strong> {_esc(baseline_meta.get('zabbix_dbversion'))}<br>
<strong>Current DB version:</strong> {_esc(current_dbversion)}<br>
<strong>Thresholds LLD:</strong> warning ≥ {_esc(thresholds.get('warning_loss_pct'))}% · high ≥ {_esc(thresholds.get('high_loss_pct'))}% · perda absoluta mínima {_esc(thresholds.get('min_absolute_loss'))}<br>
<strong>Arquivos completos:</strong> <code>item_regressions.csv</code>, <code>lld_rule_regressions.csv</code>, <code>lld_loss_summary.csv</code>, <code>host_summary.csv</code> e, quando habilitado, <code>lld_child_anomalies.csv</code>.
</div>

<h2>Resumo das regressões de itens</h2>
{_table(['Category','Severity','Count'], item_categories)}

<h2>Resumo das regressões de LLD rules</h2>
{_table(['Category','Severity','Count'], lld_rule_categories)}

<h2>Discoveries com perda relevante</h2>
{_table(['Severity','Category','Host','Discovery','Rule ID','Baseline','Present in v7','Loss %','Disabled','Pending disable'], lld_loss)}

<h2>Itens com regressão — primeiros {row_limit}</h2>
{_table(['Severity','Category','Host','Item ID','Item','Key','Current error','Changed fields','Broken master','Direct dependents affected'], item_rows)}

<h2>LLD rules com regressão — primeiros {row_limit}</h2>
{_table(['Severity','Category','Host','Item ID','Discovery','Key','Current error','Changed fields'], lld_rule_rows)}

<h2>Possíveis causas raiz por master item</h2>
<p class="muted">Mostra itens com erro que também possuem itens dependentes em regressão.</p>
{_table(['Severity','Host','Master item ID','Master item','Key','Category','Direct dependents affected','Current error'], root_rows)}

<h2>Hosts mais impactados</h2>
{_table(['Host','Visible name','Anomalies'], host_rows)}
</main></body></html>"""
    output.write_text(page, encoding="utf-8")
    return output
