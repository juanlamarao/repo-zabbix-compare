from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .logic import LossThresholds


@dataclass
class DBConfig:
    host: str
    port: int
    database: str
    user: str
    password: str = ""
    connect_timeout: int = 10
    read_timeout: int = 600
    ssl_ca: str | None = None


@dataclass
class ReportConfig:
    warning_loss_pct: float = 20.0
    high_loss_pct: float = 50.0
    min_absolute_loss: int = 10
    batch_size: int = 5000
    html_row_limit: int = 500
    write_lld_child_details: bool = True

    @property
    def thresholds(self) -> LossThresholds:
        return LossThresholds(
            warning_pct=self.warning_loss_pct,
            high_pct=self.high_loss_pct,
            min_absolute=self.min_absolute_loss,
        )


@dataclass
class AppConfig:
    baseline: DBConfig
    current: DBConfig | None = None
    report: ReportConfig = field(default_factory=ReportConfig)


def _load_db(section: dict[str, Any] | None, name: str) -> DBConfig | None:
    if not section:
        return None

    password = section.get("password", "")
    password_env = section.get("password_env")
    if password_env:
        if password_env not in os.environ:
            raise ValueError(f"Variável de ambiente {password_env!r} não definida para {name}.")
        password = os.environ[password_env]

    required = ["host", "database", "user"]
    missing = [key for key in required if not section.get(key)]
    if missing:
        raise ValueError(f"Configuração {name}: campos obrigatórios ausentes: {', '.join(missing)}")

    return DBConfig(
        host=str(section["host"]),
        port=int(section.get("port", 3306)),
        database=str(section["database"]),
        user=str(section["user"]),
        password=str(password),
        connect_timeout=int(section.get("connect_timeout", 10)),
        read_timeout=int(section.get("read_timeout", 600)),
        ssl_ca=section.get("ssl_ca"),
    )


def load_config(path: str | Path) -> AppConfig:
    cfg_path = Path(path)
    data = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}

    baseline = _load_db(data.get("baseline"), "baseline")
    if baseline is None:
        raise ValueError("A seção 'baseline' é obrigatória.")
    current = _load_db(data.get("current"), "current")

    report_data = data.get("report", {}) or {}
    report = ReportConfig(
        warning_loss_pct=float(report_data.get("warning_loss_pct", 20.0)),
        high_loss_pct=float(report_data.get("high_loss_pct", 50.0)),
        min_absolute_loss=int(report_data.get("min_absolute_loss", 10)),
        batch_size=int(report_data.get("batch_size", 5000)),
        html_row_limit=int(report_data.get("html_row_limit", 500)),
        write_lld_child_details=bool(report_data.get("write_lld_child_details", True)),
    )

    if report.batch_size < 100 or report.batch_size > 20000:
        raise ValueError("report.batch_size deve ficar entre 100 e 20000.")
    if report.high_loss_pct < report.warning_loss_pct:
        raise ValueError("high_loss_pct deve ser >= warning_loss_pct.")

    return AppConfig(baseline=baseline, current=current, report=report)
