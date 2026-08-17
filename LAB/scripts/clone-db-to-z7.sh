#!/usr/bin/env bash
set -euo pipefail
mkdir -p backup

echo "1/6 - Gerando dump consistente do Zabbix 6..."
docker exec zbx-lab-db6 sh -lc 'mysqldump -uroot -p"$MYSQL_ROOT_PASSWORD" --single-transaction --routines --triggers --events --hex-blob --set-gtid-purged=OFF zabbix > /tmp/zabbix6.sql'
docker cp zbx-lab-db6:/tmp/zabbix6.sql ./backup/zabbix6.sql

echo "2/6 - Subindo somente db7..."
docker compose --profile z7 up -d db7

echo "3/6 - Aguardando db7..."
for _ in $(seq 1 60); do
  [ "$(docker inspect -f '{{.State.Health.Status}}' zbx-lab-db7 2>/dev/null || true)" = healthy ] && break
  sleep 2
done
[ "$(docker inspect -f '{{.State.Health.Status}}' zbx-lab-db7)" = healthy ]

echo "4/6 - Importando banco 6 no banco 7..."
docker exec zbx-lab-db7 sh -lc 'mysql -uroot -p"$MYSQL_ROOT_PASSWORD" -e "DROP DATABASE IF EXISTS zabbix; CREATE DATABASE zabbix CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;"'
docker cp ./backup/zabbix6.sql zbx-lab-db7:/tmp/zabbix6.sql
docker exec zbx-lab-db7 sh -lc 'mysql -uroot -p"$MYSQL_ROOT_PASSWORD" zabbix < /tmp/zabbix6.sql'

echo "5/6 - Subindo Zabbix 7 e executando upgrade do schema..."
docker compose --profile z7 up -d zabbix-server7

echo "6/6 - Subindo frontend 7..."
docker compose --profile z7 up -d zabbix-web7

echo "Zabbix 6: http://localhost:8086"
echo "Zabbix 7: http://localhost:8087"
echo "Logs: docker compose --profile z7 logs -f zabbix-server7"
