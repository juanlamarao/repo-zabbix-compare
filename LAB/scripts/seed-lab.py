#!/usr/bin/env python3
from __future__ import annotations
import argparse
from zabbix_api import ZabbixAPI

p=argparse.ArgumentParser(description="Cria hosts para testar coleta em lotes e adiciona itens trapper sintéticos")
p.add_argument("--url", default="http://localhost:8086/api_jsonrpc.php")
p.add_argument("--user", default="Admin")
p.add_argument("--password", default="zabbix")
p.add_argument("--hosts", type=int, default=10)
p.add_argument("--synthetic-items", type=int, default=100)
p.add_argument("--trigger-count", type=int, default=5)
a=p.parse_args()

api=ZabbixAPI(a.url)
api.login(a.user,a.password)

def ensure_group(name: str):
    rows=api.call("hostgroup.get", {"output":["groupid","name"],"filter":{"name":[name]}})
    if rows: return rows[0]["groupid"]
    return api.call("hostgroup.create", {"name":name})["groupids"][0]

def find_template(name: str):
    rows=api.call("template.get", {"output":["templateid","host","name"],"filter":{"host":[name]}})
    if not rows:
        rows=api.call("template.get", {"output":["templateid","host","name"],"search":{"name":name}})
    return rows[0]["templateid"] if rows else None

groupid=ensure_group("Upgrade Validator Lab")
templateid=find_template("Linux by Zabbix agent")
if not templateid:
    print("AVISO: template 'Linux by Zabbix agent' não encontrado; hosts serão criados sem template/LDD padrão.")

for idx in range(1,a.hosts+1):
    host=f"lab-linux-{idx:03d}"
    rows=api.call("host.get", {"output":["hostid","host"],"filter":{"host":[host]}})
    if rows:
        hostid=rows[0]["hostid"]
        print(f"{host}: já existe ({hostid})")
    else:
        params={
            "host":host,
            "name":host,
            "groups":[{"groupid":groupid}],
            "interfaces":[{
                "type":1,"main":1,"useip":0,"ip":"","dns":"zabbix-agent6","port":"10050"
            }],
        }
        if templateid:
            params["templates"]=[{"templateid":templateid}]
        hostid=api.call("host.create", params)["hostids"][0]
        print(f"{host}: criado ({hostid})")

    existing=api.call("item.get", {
        "output":["itemid","key_"],"hostids":[hostid],"search":{"key_":"lab.synthetic["},"searchWildcardsEnabled":False
    })
    existing_keys={r["key_"] for r in existing}
    create=[]
    for n in range(1,a.synthetic_items+1):
        key=f"lab.synthetic[{n}]"
        if key not in existing_keys:
            create.append({
                "name":f"Synthetic metric {n}","key_":key,"hostid":hostid,
                "type":2,"value_type":0,"delay":"0"
            })
    for pos in range(0,len(create),500):
        api.call("item.create", create[pos:pos+500])
    if create:
        print(f"  + {len(create)} itens trapper")

    trig=[]
    for n in range(1,min(a.trigger_count,a.synthetic_items)+1):
        desc=f"LAB {host} synthetic {n} high"
        found=api.call("trigger.get", {"output":["triggerid"],"filter":{"description":[desc]}})
        if not found:
            trig.append({
                "description":desc,
                "expression":f"last(/{host}/lab.synthetic[{n}])>80",
                "priority":3,
            })
    if trig:
        api.call("trigger.create", trig)
        print(f"  + {len(trig)} triggers")

print("\nSeed concluído. Aguarde alguns minutos para itens do template e LLDs coletarem antes de criar a baseline.")
