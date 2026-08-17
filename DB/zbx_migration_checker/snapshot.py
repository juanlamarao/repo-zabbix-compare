from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from . import __version__
from .db import MySQLDatabase

LOG = logging.getLogger(__name__)

ITEM_COLUMNS = [
    "itemid", "hostid", "item_status", "flags", "item_type", "value_type", "key_", "name",
    "delay", "interfaceid", "master_itemid", "snmp_oid", "timeout", "templateid", "host",
    "host_name", "host_status", "proxy_ref", "rt_state", "rt_error", "interface_type",
    "interface_available", "interface_error", "interface_ip", "interface_dns", "interface_port",
]

DISCOVERY_COLUMNS = [
    "itemid", "parent_itemid", "lastcheck", "ts_delete", "discovery_status", "ts_disable",
    "disable_source",
]


def open_sqlite(path: str | Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA temp_store=MEMORY")
    conn.execute("PRAGMA cache_size=-200000")
    return conn


def create_snapshot_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE metadata (
            key TEXT PRIMARY KEY,
            value TEXT
        );

        CREATE TABLE items (
            itemid INTEGER PRIMARY KEY,
            hostid INTEGER,
            item_status INTEGER,
            flags INTEGER,
            item_type INTEGER,
            value_type INTEGER,
            key_ TEXT,
            name TEXT,
            delay TEXT,
            interfaceid INTEGER,
            master_itemid INTEGER,
            snmp_oid TEXT,
            timeout TEXT,
            templateid INTEGER,
            host TEXT,
            host_name TEXT,
            host_status INTEGER,
            proxy_ref INTEGER,
            rt_state INTEGER,
            rt_error TEXT,
            interface_type INTEGER,
            interface_available INTEGER,
            interface_error TEXT,
            interface_ip TEXT,
            interface_dns TEXT,
            interface_port TEXT
        );
        CREATE INDEX idx_items_hostid ON items(hostid);
        CREATE INDEX idx_items_flags ON items(flags);
        CREATE INDEX idx_items_baseline_health ON items(host_status, item_status, rt_state, flags);
        CREATE INDEX idx_items_master ON items(master_itemid);

        CREATE TABLE discovery (
            itemid INTEGER PRIMARY KEY,
            parent_itemid INTEGER,
            lastcheck INTEGER,
            ts_delete INTEGER,
            discovery_status INTEGER,
            ts_disable INTEGER,
            disable_source INTEGER
        );
        CREATE INDEX idx_discovery_parent ON discovery(parent_itemid);
        """
    )


def _insert_many(conn: sqlite3.Connection, table: str, columns: list[str], rows: Iterable[dict[str, Any]], batch_size: int = 10000) -> int:
    placeholders = ",".join(["?"] * len(columns))
    sql = f"INSERT INTO {table} ({','.join(columns)}) VALUES ({placeholders})"
    batch: list[tuple[Any, ...]] = []
    total = 0
    for row in rows:
        batch.append(tuple(row.get(c) for c in columns))
        if len(batch) >= batch_size:
            conn.executemany(sql, batch)
            conn.commit()
            total += len(batch)
            batch.clear()
            if total % 100000 == 0:
                LOG.info("Snapshot: %s registros gravados em %s", f"{total:,}", table)
    if batch:
        conn.executemany(sql, batch)
        conn.commit()
        total += len(batch)
    return total


def create_snapshot(db: MySQLDatabase, output_path: str | Path, force: bool = False) -> Path:
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        if not force:
            raise FileExistsError(f"Snapshot já existe: {output}. Use --force para sobrescrever.")
        output.unlink()

    errors = db.validate_required_schema()
    if errors:
        raise RuntimeError("Schema Zabbix inválido:\n- " + "\n- ".join(errors))

    LOG.info("Criando snapshot de %s@%s/%s", db.cfg.user, db.cfg.host, db.cfg.database)
    conn = open_sqlite(output)
    try:
        create_snapshot_schema(conn)
        version = db.db_version()
        metadata = {
            "checker_version": __version__,
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "source_host": db.cfg.host,
            "source_port": db.cfg.port,
            "source_database": db.cfg.database,
            "zabbix_dbversion": version,
            "schema_features": {
                "item_rtdata": db.schema.has_table("item_rtdata"),
                "item_discovery": db.schema.has_table("item_discovery"),
                "item_discovery_status": db.schema.has_column("item_discovery", "status"),
                "item_discovery_ts_disable": db.schema.has_column("item_discovery", "ts_disable"),
                "item_discovery_disable_source": db.schema.has_column("item_discovery", "disable_source"),
            },
        }
        conn.executemany(
            "INSERT INTO metadata(key, value) VALUES (?, ?)",
            [(k, json.dumps(v, ensure_ascii=False)) for k, v in metadata.items()],
        )
        conn.commit()

        item_count = _insert_many(conn, "items", ITEM_COLUMNS, db.stream_all_items())
        LOG.info("Snapshot: %s itens coletados", f"{item_count:,}")

        discovery_count = _insert_many(conn, "discovery", DISCOVERY_COLUMNS, db.stream_all_discovery())
        LOG.info("Snapshot: %s relações LLD coletadas", f"{discovery_count:,}")

        conn.execute("INSERT OR REPLACE INTO metadata(key, value) VALUES (?, ?)", ("item_count", json.dumps(item_count)))
        conn.execute("INSERT OR REPLACE INTO metadata(key, value) VALUES (?, ?)", ("discovery_count", json.dumps(discovery_count)))
        conn.commit()
        conn.execute("PRAGMA optimize")
    finally:
        conn.close()

    LOG.info("Snapshot concluído: %s", output)
    return output


def read_metadata(snapshot_path: str | Path) -> dict[str, Any]:
    conn = open_sqlite(snapshot_path)
    try:
        rows = conn.execute("SELECT key, value FROM metadata").fetchall()
        return {row["key"]: json.loads(row["value"]) for row in rows}
    finally:
        conn.close()
