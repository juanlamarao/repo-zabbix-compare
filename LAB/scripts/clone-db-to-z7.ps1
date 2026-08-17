$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path backup | Out-Null

Write-Host "1/6 - Gerando dump consistente do Zabbix 6..."
docker exec zbx-lab-db6 sh -lc 'mysqldump -uroot -p"$MYSQL_ROOT_PASSWORD" --single-transaction --routines --triggers --events --hex-blob --set-gtid-purged=OFF zabbix > /tmp/zabbix6.sql'
docker cp zbx-lab-db6:/tmp/zabbix6.sql ./backup/zabbix6.sql

Write-Host "2/6 - Subindo somente o MySQL do ambiente 7..."
docker compose --profile z7 up -d db7

Write-Host "3/6 - Aguardando db7 ficar healthy..."
for ($i=0; $i -lt 60; $i++) {
  $status = docker inspect -f '{{.State.Health.Status}}' zbx-lab-db7 2>$null
  if ($status -eq 'healthy') { break }
  Start-Sleep -Seconds 2
}
if ((docker inspect -f '{{.State.Health.Status}}' zbx-lab-db7) -ne 'healthy') { throw "db7 não ficou healthy" }

Write-Host "4/6 - Recriando database destino e importando cópia do Zabbix 6..."
docker exec zbx-lab-db7 sh -lc 'mysql -uroot -p"$MYSQL_ROOT_PASSWORD" -e "DROP DATABASE IF EXISTS zabbix; CREATE DATABASE zabbix CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;"'
docker cp ./backup/zabbix6.sql zbx-lab-db7:/tmp/zabbix6.sql
docker exec zbx-lab-db7 sh -lc 'mysql -uroot -p"$MYSQL_ROOT_PASSWORD" zabbix < /tmp/zabbix6.sql'

Write-Host "5/6 - Subindo Zabbix Server 7.0 (ele fará o upgrade do schema da cópia)..."
docker compose --profile z7 up -d zabbix-server7

Write-Host "6/6 - Subindo frontend 7.0..."
docker compose --profile z7 up -d zabbix-web7

Write-Host ""
Write-Host "Zabbix 6: http://localhost:8086"
Write-Host "Zabbix 7: http://localhost:8087"
Write-Host "Acompanhe o upgrade: docker compose --profile z7 logs -f zabbix-server7"
