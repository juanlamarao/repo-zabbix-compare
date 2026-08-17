# Zabbix DB Migration Checker — 6 → 7

Comparador **read-only** de bancos MySQL/MariaDB do Zabbix. O Zabbix 6 é a fonte da verdade e o `itemid` é a chave de correlação.

## O que ele valida

- Itens que estavam saudáveis no Zabbix 6 e no 7 ficaram:
  - ausentes;
  - em host ausente;
  - desabilitados;
  - `Not supported`;
  - sem `item_rtdata` correspondente.
- Mensagem de erro do item (`item_rtdata.error`) e erro/availability da interface em campos separados. O erro de interface nunca substitui o erro do item.
- Hosts que estavam monitorados no baseline mas estão desabilitados no Zabbix 7 são excluídos da análise de regressão, inclusive das análises LLD.
- Hosts habilitados no Zabbix 7 em que **todas as interfaces** estão com erro ou indisponíveis são isolados do relatório de regressões. Seus itens, LLDs e impactos por template não entram na fila de correção até a conectividade do host ser normalizada. Esses hosts aparecem em uma tela/CSV próprios.
- Diferenças estruturais dos itens que apresentaram regressão: `hostid`, `type`, `key_`, `value_type`, `interfaceid`, `master_itemid`, `delay`, `timeout`, `snmp_oid` e `templateid`.
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
- `host_interface_failures.csv` — hosts habilitados em que 100% das interfaces estão em erro/indisponíveis;
- `host_interface_failure_details.csv` — detalhe de cada interface desses hosts e sua mensagem de erro;
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
- a existência no 7 é determinada diretamente por `items.itemid`; runtime (`item_rtdata`) e interface são coletados separadamente e mesclados por chave, evitando falsos `ITEM_MISSING` e associação cruzada de erros;
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

## Frontend web pós-migração

Depois de executar `compare` ou `run`, use o `comparison_results.sqlite` gerado para abrir o dashboard interativo:

```bash
python -m zbx_migration_checker serve \
  --results reports/pos-upgrade/comparison_results.sqlite
```

Abra no navegador:

```text
http://127.0.0.1:8088
```

Para acessar a partir de outra máquina na rede:

```bash
python -m zbx_migration_checker serve \
  --results reports/pos-upgrade/comparison_results.sqlite \
  --host 0.0.0.0 \
  --port 8088
```

> O servidor web é somente leitura e consulta apenas o `comparison_results.sqlite`. Ele não se conecta nem altera o banco do Zabbix. Por padrão escuta somente em `127.0.0.1`. Se usar `0.0.0.0`, proteja o acesso com firewall ou reverse proxy/autenticação, porque o frontend não implementa login próprio.

### O que o frontend mostra

- visão executiva da migração;
- quantidade de regressões e hosts impactados;
- categorias de erro mais frequentes;
- top hosts com maior concentração de regressões;
- tela **Falhas de interface**, contendo somente hosts habilitados em que nenhuma interface está sem erro, com interface, endpoint, disponibilidade e erro;
- perda de filhos por discovery/LLD;
- itens `Not discovered`, `Pending delete`, desabilitados e pendentes de desabilitação;
- erros de coleta mais recorrentes;
- tabela filtrável de itens em regressão;
- tabela de discoveries com percentual de perda e perda operacional;
- regras LLD quebradas;
- master items que concentram dependent items afetados;
- fila priorizada de **Ajustes recomendados** (`P0`, `P1`, `P2`) gerada a partir das evidências da comparação.

A aba de ajustes prioriza causa raiz. Por exemplo, se um master item está quebrado e possui centenas de dependentes em regressão, o frontend recomenda corrigir o master antes dos filhos. Discoveries com perda total, regras LLD quebradas e objetos marcados para deleção recebem prioridade maior.

## v0.3.0 — agrupamento por template base

A versão 0.3 adiciona uma visão de priorização por **template base**. A origem é resolvida exclusivamente pelo snapshot do Zabbix 6, seguindo recursivamente `items.templateid` até o item raiz. Dessa forma, uma cadeia como `host -> template composto -> template base` é agrupada pelo template base real.

A tela **Templates base** apresenta, por template:

- posição no ranking de prioridade;
- quantidade de hosts afetados;
- regressões de itens;
- objetos CRITICAL/HIGH/WARNING;
- regras LLD quebradas;
- LLDs com perda e perda total;
- filhos LLD perdidos;
- filhos com deleção pendente;
- dependentes afetados;
- impacto total calculado.

O dashboard principal também exibe **Top 20 templates base para corrigir**. A ordenação dá prioridade, nesta ordem geral, a perda total de LLD, criticidade e volume impactado. O ranking é uma ferramenta de triagem; a intenção da configuração deve ser validada antes de qualquer alteração.

### Atualizar um resultado v0.2 sem consultar novamente os bancos Zabbix

Se você já possui o snapshot do Zabbix 6 e o `comparison_results.sqlite`, não precisa repetir a coleta dos bancos. Execute:

```bash
python -m zbx_migration_checker enrich-templates \
  --baseline data/zabbix6_baseline.sqlite \
  --results reports/pos-upgrade/comparison_results.sqlite
```

O comando altera somente o SQLite local de resultados e cria também:

```text
template_summary.csv
```

Depois inicie normalmente o frontend:

```bash
python -m zbx_migration_checker serve \
  --results reports/pos-upgrade/comparison_results.sqlite
```

Em novas execuções do comando `compare`, o enriquecimento de templates já ocorre automaticamente.


## v0.4.0 — correções de integridade e tabelas avançadas

A v0.4 corrige três pontos importantes encontrados durante a validação de resultados reais:

1. **Hosts desabilitados no Zabbix 7 são ignorados completamente.** Se o host está `status != 0` no ambiente atual, itens, regras LLD e filhos LLD desse host não geram regressão.
2. **Erro do item e erro da interface são independentes.** `current_error` vem somente de `item_rtdata.error`. `interface_error` continua disponível como evidência separada.
3. **`ITEM_MISSING` usa `items.itemid` como fonte de existência.** A coleta do item foi separada em três etapas: configuração/identidade, runtime e interface. Um item que existe em `items` não pode ser classificado como ausente apenas porque algum dado runtime/interface não foi encontrado.

A tabela de itens também mostra lado a lado:

- `itemid`;
- nome/key do baseline 6;
- tipo do item no 6;
- tipo do item no 7;
- key atual no 7;
- erro do item;
- erro da interface;
- campos que mudaram.

Isso ajuda a detectar imediatamente um caso em que o mesmo ID esteja associado a uma configuração diferente no ambiente novo.

### Filtros e ordenação por coluna

As tabelas de Itens, LLD, Regras LLD, Causas raiz, Templates e Hosts possuem agora:

- filtro individual abaixo de cada coluna;
- ordenação crescente/decrescente clicando no título da coluna;
- filtros processados no backend/SQLite, e não somente na página atual;
- paginação preservada para ambientes grandes.

### Auditar um resultado gerado pela v0.3

Antes de apagar seu resultado anterior, você pode verificar exatamente se ele sofreu os problemas corrigidos na v0.4:

```bash
python -m zbx_migration_checker audit-results \
  --results reports/pos-upgrade/comparison_results.sqlite
```

Para conferir os `ITEM_MISSING` antigos diretamente contra a tabela `items` do Zabbix 7:

```bash
python -m zbx_migration_checker audit-results \
  --results reports/pos-upgrade/comparison_results.sqlite \
  --config config.yml \
  --output reports/pos-upgrade/audit-v03.json
```

A auditoria informa, entre outros:

- `ITEM_MISSING` que na verdade já estavam presentes no `current_items` armazenado;
- `ITEM_MISSING` que existem atualmente em `items` no banco 7 (quando `--config` é usado);
- anomalias pertencentes a hosts atualmente desabilitados;
- casos em que o resultado antigo usou `interface_error` como se fosse o erro do item;
- divergências entre `anomalies.current_error` e `current_items.rt_error`.

### Atualizar o resultado sem refazer o snapshot do Zabbix 6

O snapshot `data/zabbix6_baseline.sqlite` continua válido. Para usar as correções da v0.4, **não é necessário extrair novamente o Zabbix 6**. Reexecute apenas a comparação contra o 7:

```bash
python -m zbx_migration_checker compare \
  --config config.yml \
  --baseline data/zabbix6_baseline.sqlite \
  --output-dir reports/pos-upgrade-v04 \
  --force
```

Depois:

```bash
python -m zbx_migration_checker serve \
  --results reports/pos-upgrade-v04/comparison_results.sqlite
```


## v0.4.1 — isolamento de falhas completas de interface

A v0.4.1 separa falha de conectividade do host de regressão de item/template. Antes de analisar itens e discoveries, o comparador coleta **todas as interfaces do host no Zabbix 7**.

Um host é isolado das regressões somente quando todas estas condições são verdadeiras:

- o host existe e está habilitado (`hosts.status = 0`);
- o host possui pelo menos uma interface;
- **nenhuma interface está sem erro**. Para esta regra, uma interface é considerada em falha quando `interface_error` não está vazio ou `available = 2`.

Se existir ao menos uma interface sem erro/indisponibilidade, o host continua na análise normal. Interfaces com `available = 0` e sem mensagem de erro não fazem o host ser isolado.

Para os hosts isolados:

- itens não entram em `item_regressions.csv`;
- regras LLD não entram nas regressões;
- perdas LLD desses hosts não entram no ranking;
- o host não contamina o Top 20 de templates;
- o host não entra em causas raiz/dependentes;
- os dados aparecem na aba **Falhas de interface** e nos CSVs `host_interface_failures.csv` e `host_interface_failure_details.csv`.

A aba mostra uma linha por interface, com host, `hostid`, `interfaceid`, tipo (Agent/SNMP/IPMI/JMX), interface principal, endpoint, disponibilidade, erro e proxy. A tabela possui filtros e ordenação por coluna.

Não é necessário refazer o snapshot do Zabbix 6. Reexecute somente a comparação com esta versão:

```bash
python -m zbx_migration_checker compare \
  --config config.yml \
  --baseline data/zabbix6_baseline.sqlite \
  --output-dir reports/pos-upgrade-v041 \
  --force
```

Depois abra o frontend:

```bash
python -m zbx_migration_checker serve \
  --results reports/pos-upgrade-v041/comparison_results.sqlite
```
