# Zabbix Upgrade Validator — Zabbix 6 → 7

MVP para tirar uma fotografia funcional do Zabbix 6 e validar continuamente o Zabbix 7 durante um upgrade/cutover.

## O que já está implementado

- baseline apenas de **hosts ativos**;
- itens habilitados/saudáveis no baseline (`status=0`, `state=0`, sem erro e não marcados para remoção LLD);
- triggers habilitadas e com avaliação saudável, mantendo `OK/PROBLEM` como informação secundária;
- interfaces e disponibilidade;
- regras LLD e retenção;
- relação `LLD → prototype → filhos` para itens e triggers descobertos;
- detector de `LLD_ZERO_DISCOVERY`;
- detector de filhos `lost`, `ts_delete` e `ts_disable`;
- comparação de quantidade de filhos por prototype;
- proxies comparados por `proxyid`, não por nome;
- Actions e Media Types;
- últimas 3 execuções de cada Action agrupadas por `eventid` usando `alert.get`;
- diferenças esperadas para:
  - proxy renomeado temporariamente;
  - Action desabilitada durante cutover;
  - Media Type desabilitada durante cutover;
- coleta em lotes configuráveis;
- padrão inicial: **5 hosts/lote × 5 lotes paralelos**;
- coleta pós-upgrade periódica;
- ciclos não concorrentes;
- dashboard nunca publica um ciclo parcial;
- evolução temporal de `% de itens com nova coleta`;
- PostgreSQL próprio, sem consultar diretamente o banco do Zabbix.

## Estratégia de armazenamento

O estado de milhões de itens não é duplicado a cada 5 minutos.

O banco mantém:

1. uma baseline imutável;
2. dois slots reutilizáveis de estado atual;
3. métricas agregadas por ciclo;
4. eventos de regressão.

O worker escreve no slot inativo. Somente depois que todos os hosts terminam é feito o `flip` do slot ativo. Isso evita exibir falsos desaparecimentos enquanto 40%, 60% ou 90% do ambiente ainda está sendo coletado.

## Requisitos do usuário/API Zabbix

Crie API Tokens dedicados no Zabbix 6 e no Zabbix 7. O usuário/role precisa enxergar todos os hosts/proxies monitorados e ter permissão para as APIs usadas.

Para `action.get`, `mediatype.get` e principalmente `alert.get`, prefira um usuário **Super Admin** dedicado ao validador. Dependendo da versão 7.0.x e do role, `alert.get` pode limitar alertas de usuários Admin/User. Se `alert.get` for bloqueado, a fotografia principal continua funcionando, porém as três execuções de Actions ficarão vazias.

## Subir

```bash
cp .env.example .env
nano .env

docker compose up -d --build
```

Acesse:

```text
http://SEU_SERVIDOR:8080
```

Teste as duas APIs:

```bash
curl http://127.0.0.1:8080/api/zabbix/test
```

## Fluxo recomendado da mudança

1. Preencha `OLD_ZABBIX_URL/TOKEN` apontando para o Zabbix 6.
2. Preencha `NEW_ZABBIX_URL/TOKEN` para o endpoint que será usado pelo Zabbix 7.
3. Abra o portal e crie a fotografia.
4. Espere a baseline ficar `READY`.
5. Confira os totais.
6. Clique em **Congelar**.
7. Faça o cutover/upgrade.
8. O worker inicia as coletas do Zabbix 7 automaticamente no intervalo configurado.
9. Se necessário, clique em **Executar coleta agora**.
10. Marque renomeações/inibições intencionais como esperadas nas telas de Proxy/Actions/Media Types.
11. Acompanhe a evolução até o critério de aceite.

## Como a saúde é interpretada

### Item

Um item do baseline entra no denominador somente se estava:

- habilitado;
- `state=0`;
- sem `error`;
- não estava perdido/aguardando remoção por LLD.

No Zabbix 7 ele fica **validado** somente quando continua saudável e:

```text
lastclock_atual > lastclock_baseline
```

Ou seja: existir no banco/configuração não basta; precisa ter ocorrido coleta nova.

### Trigger

A validação funcional usa:

- `status`;
- `state`;
- `error`;
- existência do mesmo `triggerid`.

Mudança `OK ↔ PROBLEM` é contada separadamente e não é automaticamente classificada como falha de upgrade.

### LLD

Para cada LLD e prototype são mantidos:

- filhos saudáveis no baseline;
- filhos existentes agora;
- filhos atualmente descobertos;
- filhos lost;
- filhos com exclusão agendada;
- filhos com desabilitação agendada.

Se o baseline tinha filhos e o atual tem `0` descobertos, o portal cria um evento `LLD_ZERO_DISCOVERY` como `CRITICAL`.

## Ajustando carga

Comece com:

```env
HOSTS_PER_BATCH=5
PARALLEL_BATCHES=5
```

Isso significa até 5 requisições/lotes concorrentes, cada lote trabalhando com 5 hosts. Dentro de cada lote o coletor executa sequencialmente interfaces → itens → LLD → triggers.

Se o Zabbix/API estiver confortável, aumente gradualmente. Se houver timeout, reduza os dois parâmetros ou aumente `REQUEST_TIMEOUT_SECONDS`.

## Endpoints úteis

```text
GET  /api/health
GET  /api/zabbix/test
POST /api/baselines
GET  /api/baselines
POST /api/baselines/{id}/freeze
POST /api/cycles/run
GET  /api/dashboard
GET  /api/cycles/history
GET  /api/lld/regressions
GET  /api/items/regressions?kind=problem
GET  /api/items/regressions?kind=pending
GET  /api/proxies
GET  /api/actions
GET  /api/media-types
GET  /api/expected-changes
POST /api/expected-changes
```

## Observações para o primeiro teste

Antes de apontar para os 3+ milhões de itens, valide em uma cópia/lab ou em um Zabbix com poucos hosts para confirmar permissões do API token e o comportamento específico da sua release 6.0.x / 7.0.x.

Este pacote é um MVP operacional. Para uma fase seguinte, os candidatos naturais são autenticação do portal, filtro por host group/proxy, exportação de evidências, critério de aceite configurável e teste manual/registrado de Actions críticas.


## Uso antecipado somente com Zabbix 6

A partir da v0.1.1, `NEW_ZABBIX_URL` e `NEW_ZABBIX_TOKEN` podem permanecer vazios durante a preparação.
Você pode criar a fotografia, revisar os totais e **congelar a baseline** dias antes do ambiente 7 estar disponível.
O worker permanecerá ocioso, exibindo o estado de espera, sem criar ciclos com falha.
Quando o Zabbix 7 estiver pronto, preencha as duas variáveis e reinicie `backend` e `worker`; a próxima coleta será executada normalmente.

Exemplo inicial:
```env
OLD_ZABBIX_URL=https://zabbix6/zabbix/api_jsonrpc.php
OLD_ZABBIX_TOKEN=...
NEW_ZABBIX_URL=
NEW_ZABBIX_TOKEN=
```

Depois do cutover:
```env
NEW_ZABBIX_URL=https://zabbix7/zabbix/api_jsonrpc.php
NEW_ZABBIX_TOKEN=...
```

```bash
docker compose up -d --force-recreate backend worker
```
