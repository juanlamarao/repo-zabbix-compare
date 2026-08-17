from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Iterable, Iterator, Sequence

try:
    import pymysql
    from pymysql.cursors import DictCursor, SSDictCursor
except ImportError:  # allows offline unit tests that use a fake DB adapter
    pymysql = None
    DictCursor = SSDictCursor = object

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
    """Read-only accessor for a Zabbix MySQL/MariaDB database.

    Important design choice in v0.4: item existence/configuration is fetched from
    `items` first, then runtime/interface information is fetched separately and
    merged by the relevant primary key. This makes it impossible for a runtime
    or interface join to accidentally make an existing item look missing and it
    also prevents errors from one object being associated with another item.
    """

    def __init__(self, cfg: DBConfig):
        if pymysql is None:
            raise RuntimeError("PyMySQL não está instalado. Execute: pip install -r requirements.txt")
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

    def _core_item_select_sql(self, item_ids_count: int | None = None) -> str:
        """Fetch item identity/configuration and host data only.

        No item_rtdata/interface tables are joined here. An item that exists in
        `items` therefore always comes back from this query.
        """
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
        if s.has_column("hosts", "proxy_hostid"):
            select.append("h.proxy_hostid AS proxy_ref")
        elif s.has_column("hosts", "proxyid"):
            select.append("h.proxyid AS proxy_ref")
        else:
            select.append("NULL AS proxy_ref")

        where = ""
        if item_ids_count is not None:
            where = " WHERE i.itemid IN (" + ",".join(["%s"] * item_ids_count) + ")"
        return "SELECT " + ", ".join(select) + " FROM items i LEFT JOIN hosts h ON h.hostid=i.hostid" + where

    def _fetch_rtdata(self, item_ids: Sequence[int]) -> dict[int, dict[str, Any]]:
        s = self.schema
        if not item_ids:
            return {}
        table = None
        alias = "rt"
        if s.has_table("item_rtdata") and s.has_column("item_rtdata", "itemid"):
            table = "item_rtdata"
            state_expr = "rt.state AS rt_state" if s.has_column("item_rtdata", "state") else "NULL AS rt_state"
            error_expr = "rt.error AS rt_error" if s.has_column("item_rtdata", "error") else "NULL AS rt_error"
        else:
            # Older/odd schemas may keep runtime fields on items itself.
            table = "items"
            alias = "rt"
            state_expr = "rt.state AS rt_state" if s.has_column("items", "state") else "NULL AS rt_state"
            error_expr = "rt.error AS rt_error" if s.has_column("items", "error") else "NULL AS rt_error"

        placeholders = ",".join(["%s"] * len(item_ids))
        sql = f"SELECT {alias}.itemid AS itemid,{state_expr},{error_expr} FROM {table} {alias} WHERE {alias}.itemid IN ({placeholders})"
        out: dict[int, dict[str, Any]] = {}
        with self.conn.cursor() as cur:
            cur.execute(sql, list(item_ids))
            for row in cur.fetchall():
                out[int(row["itemid"])] = {"rt_state": row.get("rt_state"), "rt_error": row.get("rt_error")}
        return out

    def _fetch_interfaces(self, interface_ids: Sequence[int]) -> dict[int, dict[str, Any]]:
        s = self.schema
        ids = sorted({int(x) for x in interface_ids if x not in (None, 0)})
        if not ids or not (s.has_table("interface") and s.has_column("interface", "interfaceid")):
            return {}

        select = [
            "inf.interfaceid AS interfaceid",
            self._col(s, "interface", "inf", "type", "interface_type"),
            self._col(s, "interface", "inf", "ip", "interface_ip"),
            self._col(s, "interface", "inf", "dns", "interface_dns"),
            self._col(s, "interface", "inf", "port", "interface_port"),
        ]
        join = ""
        if s.has_table("interface_rtdata") and s.has_column("interface_rtdata", "interfaceid"):
            join = " LEFT JOIN interface_rtdata irt ON irt.interfaceid=inf.interfaceid"
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

        placeholders = ",".join(["%s"] * len(ids))
        sql = f"SELECT {', '.join(select)} FROM interface inf{join} WHERE inf.interfaceid IN ({placeholders})"
        out: dict[int, dict[str, Any]] = {}
        with self.conn.cursor() as cur:
            cur.execute(sql, ids)
            for row in cur.fetchall():
                # interfaceid is the merge key; even if a nonstandard schema
                # returns duplicates, never merge by row position.
                out[int(row["interfaceid"])] = dict(row)
        return out

    @staticmethod
    def _empty_runtime_interface(row: dict[str, Any]) -> dict[str, Any]:
        row.update(
            {
                "rt_state": None,
                "rt_error": None,
                "interface_type": None,
                "interface_available": None,
                "interface_error": None,
                "interface_ip": None,
                "interface_dns": None,
                "interface_port": None,
            }
        )
        return row

    def fetch_items(self, item_ids: Sequence[int]) -> list[dict[str, Any]]:
        """Fetch requested items with deterministic key-based merging.

        `items.itemid` is the source of truth for existence. Runtime data is
        merged by itemid and interface data by interfaceid, never by result-row
        position. This fixes false ITEM_MISSING reports and cross-item error
        attribution that can happen when a large joined result is trusted as a
        single denormalized source.
        """
        if not item_ids:
            return []
        sql = self._core_item_select_sql(len(item_ids))
        with self.conn.cursor() as cur:
            cur.execute(sql, list(item_ids))
            core_rows = [self._empty_runtime_interface(dict(r)) for r in cur.fetchall()]

        # Defensive duplicate detection. items.itemid should be unique.
        seen: set[int] = set()
        deduped: list[dict[str, Any]] = []
        for row in core_rows:
            iid = int(row["itemid"])
            if iid in seen:
                LOG.warning("Itemid duplicado retornado pela consulta core: %s", iid)
                continue
            seen.add(iid)
            deduped.append(row)

        rt = self._fetch_rtdata([int(r["itemid"]) for r in deduped])
        interfaces = self._fetch_interfaces([r.get("interfaceid") for r in deduped if r.get("interfaceid")])
        for row in deduped:
            iid = int(row["itemid"])
            if iid in rt:
                row.update(rt[iid])
            interfaceid = row.get("interfaceid")
            if interfaceid not in (None, 0) and int(interfaceid) in interfaces:
                inf = interfaces[int(interfaceid)]
                for key in (
                    "interface_type",
                    "interface_available",
                    "interface_error",
                    "interface_ip",
                    "interface_dns",
                    "interface_port",
                ):
                    row[key] = inf.get(key)
        return deduped

    def stream_all_items(self, fetch_size: int = 10000) -> Iterator[dict[str, Any]]:
        """Stream all items while keeping deterministic enrichment.

        Streaming directly from a large multi-table join was removed in v0.4.
        We stream item IDs from the authoritative items table and enrich them in
        chunks. This costs a few more indexed queries but is safer for migration
        validation and still bounded in memory.
        """
        with self.conn.cursor(SSDictCursor) as cur:
            cur.execute("SELECT itemid FROM items ORDER BY itemid")
            while True:
                rows = cur.fetchmany(fetch_size)
                if not rows:
                    break
                ids = [int(r["itemid"]) for r in rows]
                fetched = self.fetch_items(ids)
                by_id = {int(r["itemid"]): r for r in fetched}
                for iid in ids:
                    if iid in by_id:
                        yield by_id[iid]

    def fetch_item_presence(self, item_ids: Sequence[int]) -> dict[int, dict[str, Any]]:
        """Minimal direct existence check used by integrity diagnostics."""
        if not item_ids:
            return {}
        placeholders = ",".join(["%s"] * len(item_ids))
        sql = f"""
            SELECT i.itemid,i.hostid,i.status AS item_status,i.flags,i.type AS item_type,
                   i.value_type,i.key_ AS key_,i.name AS name,i.interfaceid,i.master_itemid,i.templateid,
                   h.host,h.name AS host_name,h.status AS host_status
            FROM items i
            LEFT JOIN hosts h ON h.hostid=i.hostid
            WHERE i.itemid IN ({placeholders})
        """
        with self.conn.cursor() as cur:
            cur.execute(sql, list(item_ids))
            return {int(r["itemid"]): dict(r) for r in cur.fetchall()}

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

    def fetch_host_interfaces(self, host_ids: Sequence[int]) -> list[dict[str, Any]]:
        """Return every interface for the requested hosts, enriched with runtime state.

        This is intentionally host-centric instead of item-centric.  It is used
        to identify hosts for which *all* interfaces are failing, so item/LLD
        regressions caused by a host-wide connectivity problem can be removed
        from the migration regression report and shown in a dedicated screen.
        """
        if not host_ids:
            return []
        s = self.schema
        if not (s.has_table("interface") and s.has_column("interface", "hostid")):
            return []

        select = [
            self._col(s, "interface", "inf", "interfaceid"),
            self._col(s, "interface", "inf", "hostid"),
            self._col(s, "interface", "inf", "type", "interface_type"),
            self._col(s, "interface", "inf", "main", "interface_main"),
            self._col(s, "interface", "inf", "useip", "interface_useip"),
            self._col(s, "interface", "inf", "ip", "interface_ip"),
            self._col(s, "interface", "inf", "dns", "interface_dns"),
            self._col(s, "interface", "inf", "port", "interface_port"),
        ]
        join = ""
        if s.has_table("interface_rtdata") and s.has_column("interface_rtdata", "interfaceid"):
            join = " LEFT JOIN interface_rtdata irt ON irt.interfaceid=inf.interfaceid"
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

        placeholders = ",".join(["%s"] * len(host_ids))
        sql = f"SELECT {', '.join(select)} FROM interface inf{join} WHERE inf.hostid IN ({placeholders}) ORDER BY inf.hostid, inf.interfaceid"
        with self.conn.cursor() as cur:
            cur.execute(sql, list(host_ids))
            return [dict(r) for r in cur.fetchall()]
