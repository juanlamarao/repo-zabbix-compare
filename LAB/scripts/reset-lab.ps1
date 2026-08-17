docker compose --profile z7 down -v --remove-orphans
Remove-Item -Force -ErrorAction SilentlyContinue .\backup\zabbix6.sql
