from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any
import httpx


class ZabbixAPIError(RuntimeError):
    pass


@dataclass(slots=True)
class ZabbixEndpoint:
    url: str
    token: str
    verify_ssl: bool = True
    timeout: int = 90
    retries: int = 3


class ZabbixClient:
    def __init__(self, endpoint: ZabbixEndpoint):
        self.endpoint = endpoint
        self._request_id = 0
        self._version: str | None = None
        self._client = httpx.AsyncClient(
            timeout=endpoint.timeout,
            verify=endpoint.verify_ssl,
            headers={"Content-Type": "application/json-rpc"},
        )

    async def close(self) -> None:
        await self._client.aclose()

    async def version(self) -> str:
        if self._version is None:
            self._version = str(await self.call("apiinfo.version", {}, authenticated=False))
        return self._version

    async def major(self) -> int:
        return int((await self.version()).split(".")[0])

    async def call(self, method: str, params: Any, authenticated: bool = True) -> Any:
        if not self.endpoint.url:
            raise ZabbixAPIError("URL da API Zabbix não configurada")

        self._request_id += 1
        payload: dict[str, Any] = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": self._request_id,
        }
        headers: dict[str, str] = {}
        if authenticated:
            if not self.endpoint.token:
                raise ZabbixAPIError("API token não configurado")
            major = int((self._version or "6").split(".")[0])
            if major >= 7:
                headers["Authorization"] = f"Bearer {self.endpoint.token}"
            else:
                payload["auth"] = self.endpoint.token

        last_exc: Exception | None = None
        for attempt in range(self.endpoint.retries + 1):
            try:
                response = await self._client.post(self.endpoint.url, json=payload, headers=headers)
                response.raise_for_status()
                body = response.json()
                if "error" in body:
                    error = body["error"]
                    raise ZabbixAPIError(f"{method}: {error.get('message')}: {error.get('data')}")
                return body.get("result")
            except (httpx.HTTPError, ValueError, ZabbixAPIError) as exc:
                last_exc = exc
                if attempt >= self.endpoint.retries:
                    break
                await asyncio.sleep(min(2**attempt, 8))
        raise ZabbixAPIError(str(last_exc))

    async def active_hosts(self) -> list[dict[str, Any]]:
        return await self.call(
            "host.get",
            {
                "output": ["hostid", "host", "name", "status", "proxyid", "maintenance_status"],
                "filter": {"status": 0},
                "sortfield": "hostid",
            },
        )

    async def hosts_by_ids(self, hostids: list[int]) -> list[dict[str, Any]]:
        return await self.call(
            "host.get",
            {
                "output": ["hostid", "host", "name", "status", "proxyid", "maintenance_status"],
                "hostids": [str(v) for v in hostids],
            },
        )

    async def host_batch(self, hostids: list[int]) -> dict[str, list[dict[str, Any]]]:
        major = await self.major()
        ids = [str(v) for v in hostids]

        interfaces = await self.call(
            "hostinterface.get",
            {
                "output": [
                    "interfaceid", "hostid", "type", "main", "useip", "ip", "dns", "port",
                    "available", "error", "errors_from", "disable_until",
                ],
                "hostids": ids,
            },
        )

        item_discovery_fields = ["parent_itemid", "lastcheck", "ts_delete"]
        trigger_discovery_fields = ["parent_triggerid"]
        if major >= 7:
            item_discovery_fields += ["status", "ts_disable", "disable_source"]
            trigger_discovery_fields += ["status", "ts_delete", "ts_disable", "disable_source"]

        items = await self.call(
            "item.get",
            {
                "output": [
                    "itemid", "hostid", "interfaceid", "name", "key_", "type", "status", "state",
                    "error", "lastclock", "lastvalue", "delay", "flags",
                ],
                "hostids": ids,
                "selectItemDiscovery": item_discovery_fields,
                "selectDiscoveryRule": ["itemid", "name"],
            },
        )

        lld_output = ["itemid", "hostid", "name", "key_", "status", "state", "error", "delay", "lifetime"]
        if major >= 7:
            lld_output += ["lifetime_type", "enabled_lifetime", "enabled_lifetime_type"]
        llds = await self.call(
            "discoveryrule.get",
            {"output": lld_output, "hostids": ids},
        )

        triggers = await self.call(
            "trigger.get",
            {
                "output": [
                    "triggerid", "description", "status", "state", "value", "error",
                    "lastchange", "priority", "flags",
                ],
                "hostids": ids,
                "selectTriggerDiscovery": trigger_discovery_fields,
                "selectDiscoveryRule": ["itemid", "name"],
            },
        )
        return {"interfaces": interfaces, "items": items, "llds": llds, "triggers": triggers}

    async def network_discovery_rules(self) -> list[dict[str, Any]]:
        return await self.call("drule.get", {"output": "extend"})

    async def proxies(self) -> list[dict[str, Any]]:
        return await self.call("proxy.get", {"output": "extend"})

    async def actions(self) -> list[dict[str, Any]]:
        return await self.call(
            "action.get",
            {"output": ["actionid", "name", "status", "eventsource"]},
        )

    async def media_types(self) -> list[dict[str, Any]]:
        return await self.call(
            "mediatype.get",
            {"output": ["mediatypeid", "name", "type", "status", "maxattempts", "description"]},
        )

    async def recent_alerts_for_action(
        self, actionid: int, limit: int = 100, time_from: int | None = None
    ) -> list[dict[str, Any]]:
        params: dict[str, Any] = {
                "output": [
                    "alertid", "actionid", "eventid", "clock", "mediatypeid",
                    "status", "error", "esc_step", "alerttype",
                ],
                "actionids": [str(actionid)],
                "sortfield": ["clock", "alertid"],
                "sortorder": "DESC",
                "limit": limit,
            }
        if time_from is not None:
            params["time_from"] = time_from
        return await self.call("alert.get", params)
