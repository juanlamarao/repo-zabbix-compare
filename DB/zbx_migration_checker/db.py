from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Iterable, Iterator, Sequence

import pymysql
from pymysql.cursors import DictCursor, SSDictCursor

from .config import DBConfig

LOG = logging.getLogger(__name__)


@dataclass
class SchemaInfo:
    tables: set[str]
    columns: dict[str, set[str]]

    def has_table(self, table: str) -> bool:
        return table in self.tables

    def has_column(self, table: str, column: str) -> bool:
        return column in self.columns.get(table, set())


def chunks(values: Iterable[int], size: int) -> Iterator[list[int]]:
    buf: list[int] = []
    for value in values:
        buf.append(int(value))
        if len(buf) >= size:
            yield buf
            buf = []
    if buf:
        yield buf


class MySQLDatabase:
    def __init__(self, cfg: DBConfig):
        self.cfg = cfg
        ssl = {"ca": cfg.ssl_ca} if cfg.ssl_ca else None
        self.conn = pymysql.connect(
            host=cfg.host,
            port=cfg.port,
            user=cfg.user,
            password=cfg.password,
            database=cfg.database,
            charset="utf8mb4",
            autocommit=True,
            connect_timeout=cfg.connect_timeout,
            read_timeout=cfg.read_timeout,
            write_timeout=30,
            cursorclass=DictCursor,
            ssl=ssl,
        )
        self.schema = self._inspect_schema()

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "MySQLDatabase":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def _inspect_schema(self) -> SchemaInfo:
        with self.conn.cursor() as cur:
            cur.execute(
                """
                SELECT TABLE_NAME, COLUMN_NAME
                FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA = DATABASE()
                ORDER BY TABLE_NAME, ORDINAL_POSITION
                """
            )
            columns: dict[str, set[str]] = {}
            for row in cur.fetchall():
                columns.setdefault(row["TABLE_NAME"], set()).add(row["COLUMN_NAME"])
        return SchemaInfo(set(columns), columns)

    def validate_required_schema(self) -> list[str]:
        errors: list[str] = []
        for table in ("items", "hosts"):
            if not self.schema.has_table(table):
                errors.append(f"Tabela obrigatória ausente: {table}")
        for col in ("itemid", "hostid", "status", "flags", "key_", "name"):
            if not self.schema.has_column("items", col):
                errors.append(f"Coluna obrigatória ausente: items.{col}")
        if not self.schema.has_column("hosts", "hostid"):
            errors.append("Coluna obrigatória ausente: hosts.hostid")
        return errors

    def db_version(self) -> dict[str, Any]:
        if not self.schema.has_table("dbversion"):
            return {"mandatory": None, "optional": None}
        cols = self.schema.columns["dbversion"]
        select = []
        select.append("mandatory" if "mandatory" in cols else "NULL AS mandatory")
        select.append("optional" if "optional" in cols else "NULL AS optional")
        with self.conn.cursor() as cur:
            cur.execute(f"SELECT {', '.join(select)} FROM dbversion LIMIT 1")
            row = cur.fetchone() or {}
        return row

    @staticmethod
    def _col(schema: SchemaInfo, table: str, alias: str, column: str, out: str | None = None) -> str:
        out = out or column
        if schema.has_column(table, column):
            return f"{alias}.`{column}` AS `{out}`"
        return f"NULL AS `{out}`"

    def item_select_sql(self, item_ids_count: int | None = None) -> str:
        s = self.schema
        select = [
            self._col(s, "items", "i", "itemid"),
            self._col(s, "items", "i", "hostid"),
            self._col(s, "items", "i", "status", "item_status"),
            self._col(s, "items", "i", "flags"),
            self._col(s, "items", "i", "type", "item_type"),
            self._col(s, "items", "i", "value_type"),
            self._col(s, "items", "i", "key_"),
            self._col(s, "items", "i", "name"),
            self._col(s, "items", "i", "delay"),
            self._col(s, "items", "i", "interfaceid"),
            self._col(s, "items", "i", "master_itemid"),
            self._col(s, "items", "i", "snmp_oid"),
            self._col(s, "items", "i", "timeout"),
            self._col(s, "items", "i", "templateid"),
            self._col(s, "hosts", "h", "host"),
            self._col(s, "hosts", "h", "name", "host_name"),
            self._col(s, "hosts", "h", "status", "host_status"),
        ]

        # Zabbix versions differ in how proxy assignment is represented.
        if s.has_column("hosts", "proxy_hostid"):
            select.append("h.proxy_hostid AS proxy_ref")
        elif s.has_column("hosts", "proxyid"):
            select.append("h.proxyid AS proxy_ref")
        else:
            select.append("NULL AS proxy_ref")

        joins = ["LEFT JOIN hosts h ON h.hostid = i.hostid"]

        # Runtime item state/error moved across schemas over Zabbix history.
        # Prefer item_rtdata when available, but fall back to items.* if a
        # particular patch level keeps either field there.
        if s.has_table("item_rtdata") and s.has_column("item_rtdata", "itemid"):
            joins.append("LEFT JOIN item_rtdata rt ON rt.itemid = i.itemid")
            if s.has_column("item_rtdata", "state"):
                select.append("rt.state AS rt_state")
            elif s.has_column("items", "state"):
                select.append("i.state AS rt_state")
            else:
                select.append("NULL AS rt_state")
            if s.has_column("item_rtdata", "error"):
                select.append("rt.error AS rt_error")
            elif s.has_column("items", "error"):
                select.append("i.error AS rt_error")
            else:
                select.append("NULL AS rt_error")
        else:
            select.append("i.state AS rt_state" if s.has_column("items", "state") else "NULL AS rt_state")
            select.append("i.error AS rt_error" if s.has_column("items", "error") else "NULL AS rt_error")

        # Static interface data and runtime availability are schema-adaptive.
        can_join_interface = (
            s.has_table("interface")
            and s.has_column("interface", "interfaceid")
            and s.has_column("items", "interfaceid")
        )
        if can_join_interface:
            joins.append("LEFT JOIN interface inf ON inf.interfaceid = i.interfaceid")
            select.append(self._col(s, "interface", "inf", "type", "interface_type"))
            select.append(self._col(s, "interface", "inf", "ip", "interface_ip"))
            select.append(self._col(s, "interface", "inf", "dns", "interface_dns"))
            select.append(self._col(s, "interface", "inf", "port", "interface_port"))

            if s.has_table("interface_rtdata") and s.has_column("interface_rtdata", "interfaceid"):
                joins.append("LEFT JOIN interface_rtdata irt ON irt.interfaceid = i.interfaceid")
                if s.has_column("interface_rtdata", "available"):
                    select.append("irt.available AS interface_available")
                elif s.has_column("interface", "available"):
                    select.append("inf.available AS interface_available")
                else:
                    select.append("NULL AS interface_available")
                if s.has_column("interface_rtdata", "error"):
                    select.append("irt.error AS interface_error")
                elif s.has_column("interface", "error"):
                    select.append("inf.error AS interface_error")
                else:
                    select.append("NULL AS interface_error")
            else:
                select.append(self._col(s, "interface", "inf", "available", "interface_available"))
                select.append(self._col(s, "interface", "inf", "error", "interface_error"))
        else:
            select.extend(
                [
                    "NULL AS interface_type",
                    "NULL AS interface_ip",
                    "NULL AS interface_dns",
                    "NULL AS interface_port",
                    "NULL AS interface_available",
                    "NULL AS interface_error",
                ]
            )

        where = ""
        if item_ids_count is not None:
            where = " WHERE i.itemid IN (" + ",".join(["%s"] * item_ids_count) + ")"

        return "SELECT " + ", ".join(select) + " FROM items i " + " ".join(joins) + where

    def stream_all_items(self, fetch_size: int = 10000) -> Iterator[dict[str, Any]]:
        sql = self.item_select_sql()
        with self.conn.cursor(SSDictCursor) as cur:
            cur.execute(sql)
            while True:
                rows = cur.fetchmany(fetch_size)
                if not rows:
                    break
                yield from rows

    def fetch_items(self, item_ids: Sequence[int]) -> list[dict[str, Any]]:
        if not item_ids:
            return []
        sql = self.item_select_sql(len(item_ids))
        with self.conn.cursor() as cur:
            cur.execute(sql, list(item_ids))
            return list(cur.fetchall())

    def discovery_select_sql(self, item_ids_count: int | None = None) -> str | None:
        s = self.schema
        if not s.has_table("item_discovery"):
            return None
        select = [
            self._col(s, "item_discovery", "d", "itemid"),
            self._col(s, "item_discovery", "d", "parent_itemid"),
            self._col(s, "item_discovery", "d", "lastcheck"),
            self._col(s, "item_discovery", "d", "ts_delete"),
            self._col(s, "item_discovery", "d", "status", "discovery_status"),
            self._col(s, "item_discovery", "d", "ts_disable"),
            self._col(s, "item_discovery", "d", "disable_source"),
        ]
        where = ""
        if item_ids_count is not None:
            where = " WHERE d.itemid IN (" + ",".join(["%s"] * item_ids_count) + ")"
        return "SELECT " + ", ".join(select) + " FROM item_discovery d" + where

    def stream_all_discovery(self, fetch_size: int = 10000) -> Iterator[dict[str, Any]]:
        sql = self.discovery_select_sql()
        if sql is None:
            return
        with self.conn.cursor(SSDictCursor) as cur:
            cur.execute(sql)
            while True:
                rows = cur.fetchmany(fetch_size)
                if not rows:
                    break
                yield from rows

    def fetch_discovery(self, item_ids: Sequence[int]) -> list[dict[str, Any]]:
        if not item_ids:
            return []
        sql = self.discovery_select_sql(len(item_ids))
        if sql is None:
            return []
        with self.conn.cursor() as cur:
            cur.execute(sql, list(item_ids))
            return list(cur.fetchall())

    def fetch_hosts(self, host_ids: Sequence[int]) -> list[dict[str, Any]]:
        if not host_ids:
            return []
        s = self.schema
        select = [
            self._col(s, "hosts", "h", "hostid"),
            self._col(s, "hosts", "h", "host"),
            self._col(s, "hosts", "h", "name", "host_name"),
            self._col(s, "hosts", "h", "status", "host_status"),
        ]
        if s.has_column("hosts", "proxy_hostid"):
            select.append("h.proxy_hostid AS proxy_ref")
        elif s.has_column("hosts", "proxyid"):
            select.append("h.proxyid AS proxy_ref")
        else:
            select.append("NULL AS proxy_ref")
        placeholders = ",".join(["%s"] * len(host_ids))
        sql = f"SELECT {', '.join(select)} FROM hosts h WHERE h.hostid IN ({placeholders})"
        with self.conn.cursor() as cur:
            cur.execute(sql, list(host_ids))
            return list(cur.fetchall())
