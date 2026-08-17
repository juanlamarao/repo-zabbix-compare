#!/usr/bin/env bash
set -e
docker compose --profile z7 down -v --remove-orphans
rm -f backup/zabbix6.sql
