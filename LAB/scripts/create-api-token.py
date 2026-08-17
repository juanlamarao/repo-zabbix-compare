#!/usr/bin/env python3
from __future__ import annotations
import argparse
from zabbix_api import ZabbixAPI

p=argparse.ArgumentParser(description="Cria um API token no Zabbix para o validator")
p.add_argument("--url", default="http://localhost:8086/api_jsonrpc.php")
p.add_argument("--user", default="Admin")
p.add_argument("--password", default="zabbix")
p.add_argument("--name", default="upgrade-validator-lab")
a=p.parse_args()

api=ZabbixAPI(a.url)
api.login(a.user,a.password)
users=api.call("user.get", {"output":["userid","username"], "filter":{"username":[a.user]}})
if not users:
    raise SystemExit(f"Usuário {a.user!r} não encontrado")
userid=users[0]["userid"]
created=api.call("token.create", {"name":a.name,"userid":userid})
tokenid=created["tokenids"][0]
generated=api.call("token.generate", [tokenid])
row=generated[0]
print("TOKEN_ID=" + str(tokenid))
print("API_TOKEN=" + row["token"])
print("\nGuarde o API_TOKEN. O segredo é exibido somente na geração.")
