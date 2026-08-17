from __future__ import annotations

import argparse
import json
import logging
from datetime import datetime
from pathlib import Path

from .config import load_config
from .db import MySQLDatabase
from .compare import compare_snapshot_to_current
from .report import generate_html
from .snapshot import create_snapshot
from .templates import enrich_existing_results
from .web import add_serve_parser

LOG = logging.getLogger(__name__)


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s - %(message)s",
    )


def _validate_one(label: str, db: MySQLDatabase) -> dict:
    errors = db.validate_required_schema()
    info = {
        "label": label,
        "server": f"{db.cfg.host}:{db.cfg.port}/{db.cfg.database}",
        "dbversion": db.db_version(),
        "errors": errors,
        "features": {
            "item_rtdata": db.schema.has_table("item_rtdata"),
            "item_discovery": db.schema.has_table("item_discovery"),
            "item_discovery.status": db.schema.has_column("item_discovery", "status"),
            "item_discovery.ts_delete": db.schema.has_column("item_discovery", "ts_delete"),
            "item_discovery.ts_disable": db.schema.has_column("item_discovery", "ts_disable"),
            "item_discovery.disable_source": db.schema.has_column("item_discovery", "disable_source"),
        },
    }
    return info


def cmd_validate(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    results = []
    with MySQLDatabase(cfg.baseline) as db:
        results.append(_validate_one("baseline", db))
    if cfg.current:
        with MySQLDatabase(cfg.current) as db:
            results.append(_validate_one("current", db))
    print(json.dumps(results, ensure_ascii=False, indent=2))
    return 1 if any(r["errors"] for r in results) else 0


def cmd_snapshot(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    with MySQLDatabase(cfg.baseline) as db:
        create_snapshot(db, args.output, force=args.force)
    return 0


def cmd_compare(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    if not cfg.current:
        raise SystemExit("A seção 'current' é obrigatória para o comando compare.")
    with MySQLDatabase(cfg.current) as db:
        results_db, summary = compare_snapshot_to_current(
            args.baseline, db, args.output_dir, cfg.report, force=args.force
        )
    report = generate_html(results_db, Path(args.output_dir) / "report.html", cfg.report.html_row_limit)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    print(f"Relatório HTML: {report}")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    if not cfg.current:
        raise SystemExit("A seção 'current' é obrigatória para o comando run.")

    run_dir = Path(args.output_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    baseline_path = run_dir / "zabbix6_baseline.sqlite"
    with MySQLDatabase(cfg.baseline) as db6:
        create_snapshot(db6, baseline_path, force=args.force)
    with MySQLDatabase(cfg.current) as db7:
        results_db, summary = compare_snapshot_to_current(
            baseline_path, db7, run_dir, cfg.report, force=args.force
        )
    report = generate_html(results_db, run_dir / "report.html", cfg.report.html_row_limit)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    print(f"Relatório HTML: {report}")
    return 0



def cmd_enrich_templates(args: argparse.Namespace) -> int:
    result = enrich_existing_results(args.results, args.baseline)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="zbx-db-migration-checker",
        description="Compara Zabbix 6 e 7 usando somente MySQL e itemids do Zabbix 6 como fonte da verdade.",
    )
    parser.add_argument("--verbose", action="store_true", help="Log detalhado")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("validate", help="Valida conexão e recursos do schema")
    p.add_argument("--config", required=True)
    p.set_defaults(func=cmd_validate)

    p = sub.add_parser("snapshot", help="Cria fotografia do Zabbix 6")
    p.add_argument("--config", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_snapshot)

    p = sub.add_parser("compare", help="Compara um snapshot do 6 contra o Zabbix 7")
    p.add_argument("--config", required=True)
    p.add_argument("--baseline", required=True)
    p.add_argument("--output-dir", required=True)
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_compare)

    p = sub.add_parser("run", help="Cria snapshot do 6 e compara com o 7 na mesma execução")
    p.add_argument("--config", required=True)
    p.add_argument("--output-dir", default=f"reports/run-{datetime.now():%Y%m%d-%H%M%S}")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("enrich-templates", help="Adiciona agrupamento por template base a um resultado já existente")
    p.add_argument("--baseline", required=True, help="Snapshot SQLite do Zabbix 6 usado como baseline")
    p.add_argument("--results", required=True, help="comparison_results.sqlite ou diretório do relatório")
    p.set_defaults(func=cmd_enrich_templates)

    add_serve_parser(sub)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    _setup_logging(args.verbose)
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        LOG.error("Execução interrompida.")
        return 130
    except Exception as exc:
        LOG.exception("Falha: %s", exc)
        return 1
