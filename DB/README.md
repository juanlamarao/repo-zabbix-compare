# Zabbix DB Migration Checker — 6 → 7

Comparador **read-only** de bancos MySQL/MariaDB do Zabbix. O Zabbix 6 é a fonte da verdade e o `itemid` é a chave de correlação.

## O que ele valida

- Itens que estavam saudáveis no Zabbix 6 e no 7 ficaram:
  - ausentes;
  - em host ausente/desabilitado;
  - desabilitados;
  - `Not supported`;
  - sem `item_rtdata` correspondente.
- Mensagem de erro atual (`item_rtdata.error`) e erro/availability da interface quando disponíveis.
- Diferenças estruturais dos itens que apresentaram regressão: `type`, `key_`, `value_type`, `interfaceid`, `master_itemid`, `delay`, `timeout` e `snmp_oid`.
- LLD rules que estavam saudáveis no 6 e quebraram no 7.
- Filhos de LLD existentes no baseline 6 que no 7:
  - desapareceram;
  - perderam o vínculo em `item_discovery`;
  - ficaram `not discovered`;
  - têm `ts_delete > 0` e portanto estão marcados para deleção;
  - foram desabilitados ou estão com `ts_disable > 0`.
- Perda percentual e absoluta por discovery, com destaque para perda total.
- Master items em regressão com dependentes também afetados.
- Agrupamento das regressões por host.

**Itens criados somente no Zabbix 7 são ignorados.** O programa nunca usa esses IDs para reduzir ou mascarar uma perda do baseline.

## Filosofia do baseline

O snapshot guarda todos os itens do banco 6 para contexto. Entretanto, uma regressão de coleta só é aberta quando, no baseline:

- host `status = 0`;
- item `status = 0`;
- `item_rtdata.state = 0`;
- item é normal (`flags = 0`) ou filho descoberto (`flags = 4`).

LLD rules (`flags = 1`) são avaliadas em uma análise própria. Item prototypes não são tratados como itens coletáveis.

Isso evita chamar de "quebrou na migração" algo que já estava desabilitado ou `Not supported` antes.

## Compatibilidade de schema

O código consulta `information_schema.COLUMNS` em tempo de execução. Assim, campos que mudam entre releases — especialmente em `item_discovery` — são detectados antes de montar as queries. Campos opcionais ausentes viram `NULL`, sem necessidade de editar SQL manualmente.

O projeto foi desenhado para Zabbix 6.0 LTS → 7.0 LTS usando apenas o banco. Antes de rodar em produção, execute `validate` para conferir as tabelas e recursos realmente existentes no seu patch level.

## Instalação local

Requer Python 3.11+.

```bash
python -m venv .venv
source .venv/bin/activate             # Linux/macOS
# .venv\\Scripts\\activate           # Windows PowerShell/CMD
pip install -r requirements.txt
cp config.example.yml config.yml
```

Defina as senhas fora do YAML:

```bash
export ZBX6_DB_PASSWORD='...'
export ZBX7_DB_PASSWORD='...'
```

No PowerShell:

```powershell
$env:ZBX6_DB_PASSWORD='...'
$env:ZBX7_DB_PASSWORD='...'
```

## 1. Validar as conexões e schemas

```bash
python -m zbx_migration_checker validate --config config.yml
```

O comando informa `dbversion` e se existem recursos como `item_rtdata`, `item_discovery.status`, `ts_delete`, `ts_disable` e `disable_source`.

## 2. Tirar a fotografia do Zabbix 6 agora

Você pode fazer isso **antes de o ambiente 7 existir**. Remova/comente a seção `current` do YAML se quiser.

```bash
python -m zbx_migration_checker snapshot \
  --config config.yml \
  --output data/zabbix6_baseline.sqlite
```

O snapshot é um SQLite local. Ele permite que a base 6 seja desligada posteriormente sem perder a referência pré-upgrade.

> Para uma fotografia estritamente consistente, prefira executar contra uma réplica/clone do banco ou em uma janela com pouca alteração de configuração. O programa não abre uma transação longa `REPEATABLE READ` na produção, evitando reter uma visão MVCC por horas em bancos muito grandes.

## 3. Comparar contra o Zabbix 7

Depois que o 7 estiver disponível:

```bash
python -m zbx_migration_checker compare \
  --config config.yml \
  --baseline data/zabbix6_baseline.sqlite \
  --output-dir reports/pos-upgrade
```

Saídas:

- `report.html` — resumo navegável;
- `summary.json` — resumo para automação;
- `item_regressions.csv` — todos os itens do baseline saudável que regrediram;
- `lld_rule_regressions.csv` — LLD rules que regrediram;
- `lld_loss_summary.csv` — perda agregada por discovery;
- `lld_child_anomalies.csv` — filhos individuais perdidos/desabilitados;
- `host_summary.csv` — agrupamento por host;
- `comparison_results.sqlite` — base completa da análise para consultas adicionais.

## Rodar 6 e 7 na mesma execução

Se os dois bancos estiverem disponíveis:

```bash
python -m zbx_migration_checker run \
  --config config.yml \
  --output-dir reports/teste-migracao
```

## Lógica de perda de LLD

Para cada filho válido do baseline 6, o programa procura **o mesmo `itemid`** no 7.

Um filho do baseline é considerado ausente para a contagem de discovery se no 7:

- o item não existe;
- o registro de `item_discovery` não existe;
- `item_discovery.status = 1`, quando a coluna existe;
- `item_discovery.ts_delete > 0`.

Desabilitação e `ts_disable > 0` são contabilizados separadamente como perda operacional.

O relatório mostra duas métricas:

- `loss_pct`: filhos do baseline que deixaram de existir efetivamente no discovery;
- `operational_loss_pct`: filhos que eram habilitados no baseline e deixaram de estar operacionalmente disponíveis no 7.

Defaults:

- warning: perda ≥ 20%;
- high: perda ≥ 50%;
- critical: perda total de 100%;
- perdas parciais menores que 10 itens são ignoradas por padrão para reduzir ruído.

A perda total sempre é `CRITICAL`, mesmo que o discovery tivesse menos de 10 filhos.

## Escala / ambiente com milhões de itens

O comparador não carrega todos os itens em RAM e não consulta as tabelas `history*` durante a análise normal.

- snapshot do 6: cursor MySQL server-side, gravação em lotes no SQLite;
- comparação do 7: busca somente os `itemid`s presentes no snapshot 6, em lotes (`batch_size`);
- novos itens do 7 não são lidos nem analisados;
- agregação de LLD é executada dentro do SQLite;
- HTML limita o número de linhas exibidas, mas os CSVs têm os registros completos.

Se houver limites de `max_allowed_packet` ou latência alta, reduza `report.batch_size` para 1000–2500.

## Usuário read-only

Há um exemplo em `sql/create_readonly_user.sql`. O comparador precisa apenas de `SELECT` na base Zabbix e acesso ao `information_schema`, que o MySQL disponibiliza de acordo com as permissões do usuário.

## Docker

```bash
cp config.example.yml config.yml
cp .env.example .env
mkdir -p data reports
docker compose build
```

Validar:

```bash
docker compose run --rm checker validate --config /app/config.yml
```

Snapshot:

```bash
docker compose run --rm checker snapshot \
  --config /app/config.yml \
  --output /app/data/zabbix6_baseline.sqlite
```

Comparar:

```bash
docker compose run --rm checker compare \
  --config /app/config.yml \
  --baseline /app/data/zabbix6_baseline.sqlite \
  --output-dir /app/reports/pos-upgrade
```

## Consultas úteis no resultado

Top master items com dependentes afetados:

```sql
SELECT itemid, host, item_name, category, dependent_affected_count, current_error
FROM anomalies
WHERE dependent_affected_count > 0
ORDER BY dependent_affected_count DESC;
```

Discoveries com perda total:

```sql
SELECT host, rule_name, ruleid, baseline_count, current_present_count
FROM lld_summary
WHERE category = 'LLD_TOTAL_LOSS'
ORDER BY baseline_count DESC;
```

Itens marcados para deleção pelo LLD:

```sql
SELECT *
FROM lld_child_anomalies
WHERE reason = 'PENDING_DELETE'
ORDER BY ruleid, itemid;
```

## Segurança e impacto

- O código não executa `INSERT`, `UPDATE`, `DELETE`, `ALTER` ou DDL nas bases Zabbix.
- Toda escrita ocorre somente nos arquivos SQLite/CSV/HTML locais.
- Evite usar usuário `root` do MySQL.
- Em produção, monitore tempo das consultas e I/O durante o primeiro snapshot.
- Para um ambiente com milhões de itens, prefira rodar o snapshot contra uma réplica de leitura se houver uma disponível.
