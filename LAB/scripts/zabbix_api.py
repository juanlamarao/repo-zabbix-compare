#!/usr/bin/env python3
from __future__ import annotations
import json
import urllib.request

class ZabbixAPI:
    def __init__(self, url: str):
        self.url = url
        self.auth: str | None = None
        self.req_id = 0

    def call(self, method: str, params, auth: bool = True):
        self.req_id += 1
        payload = {"jsonrpc":"2.0","method":method,"params":params,"id":self.req_id}
        if auth and self.auth:
            payload["auth"] = self.auth
        req = urllib.request.Request(
            self.url,
            data=json.dumps(payload).encode(),
            headers={"Content-Type":"application/json-rpc"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=60) as r:
            body = json.loads(r.read().decode())
        if "error" in body:
            e = body["error"]
            raise RuntimeError(f"{method}: {e.get('message')}: {e.get('data')}")
        return body.get("result")

    def login(self, username: str, password: str):
        self.auth = self.call("user.login", {"username": username, "password": password}, auth=False)
        return self.auth
