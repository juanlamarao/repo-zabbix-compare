#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, socket, struct, time, random

p=argparse.ArgumentParser(description="Envia valores para os itens trapper sintéticos do lab")
p.add_argument("--server", default="127.0.0.1")
p.add_argument("--port", type=int, default=10061)
p.add_argument("--hosts", type=int, default=10)
p.add_argument("--synthetic-items", type=int, default=100)
p.add_argument("--batch", type=int, default=500)
a=p.parse_args()

def send(data):
    payload=json.dumps({"request":"sender data","data":data}).encode()
    packet=b"ZBXD\x01"+struct.pack("<Q",len(payload))+payload
    with socket.create_connection((a.server,a.port),timeout=15) as s:
        s.sendall(packet)
        head=s.recv(13)
        if len(head)<13 or not head.startswith(b"ZBXD\x01"):
            raise RuntimeError("Resposta inválida do Zabbix sender")
        size=struct.unpack("<Q",head[5:13])[0]
        body=b""
        while len(body)<size:
            chunk=s.recv(size-len(body))
            if not chunk: break
            body+=chunk
        return json.loads(body.decode())

rows=[]
clock=int(time.time())
count=0
for h in range(1,a.hosts+1):
    host=f"lab-linux-{h:03d}"
    for n in range(1,a.synthetic_items+1):
        rows.append({"host":host,"key":f"lab.synthetic[{n}]","value":str(random.randint(1,100)),"clock":clock})
        if len(rows)>=a.batch:
            r=send(rows); count+=len(rows); print(f"enviados {count}: {r.get('info','ok')}"); rows=[]
if rows:
    r=send(rows); count+=len(rows); print(f"enviados {count}: {r.get('info','ok')}")
print(f"Total enviado: {count}")
