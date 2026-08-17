# Zabbix 6 -> 7 Upgrade Validation Lab

Laboratório local para reproduzir o fluxo real: manter um Zabbix 6 funcionando, criar baseline no Upgrade Validator, clonar o banco preservando IDs e iniciar um Zabbix 7 sobre a cópia para comparação.

## 1. Subir somente o Zabbix 6

```powershell
Copy-Item .env.example .env
docker compose up -d
```

Frontend: http://localhost:8086

Login inicial padrão do Zabbix: `Admin` / `zabbix`.

Confira:

```powershell
docker compose ps
docker compose logs -f zabbix-server6
```

## 2. Popular o lab

O script cria hosts apontando para o mesmo Agent2, vincula `Linux by Zabbix agent` quando disponível (o que gera itens, triggers e LLDs reais) e adiciona itens Zabbix trapper para aumentar o volume.

```powershell
python .\scripts\seed-lab.py --hosts 10 --synthetic-items 100
```

Envie valores aos itens sintéticos no Zabbix 6:

```powershell
python .\scripts\push-values.py --port 10061 --hosts 10 --synthetic-items 100
```

Aguarde alguns minutos para os itens do template e LLDs executarem.

## 3. Criar token para o Upgrade Validator

```powershell
python .\scripts\create-api-token.py --url http://localhost:8086/api_jsonrpc.php
```

Copie o `API_TOKEN` retornado.

No validator, enquanto só existe Zabbix 6:

```env
OLD_ZABBIX_URL=http://host.docker.internal:8086/api_jsonrpc.php
OLD_ZABBIX_TOKEN=<token>
NEW_ZABBIX_URL=
NEW_ZABBIX_TOKEN=
```

No Docker Desktop para Windows/macOS, `host.docker.internal` permite que um container acesse uma porta publicada no host.

## 4. Criar e congelar a baseline

Abra o Upgrade Validator, crie a fotografia e congele-a. Na v0.1.1, ele ficará em **Aguardando ambiente Zabbix 7** sem gerar ciclos com falha.

## 5. Simular a atualização 6 -> 7 preservando IDs

Não fazemos export/import de configuração. O banco do Zabbix 6 é clonado para um segundo MySQL e o Zabbix Server 7 é iniciado sobre essa cópia. Isso é importante para o teste do validator porque preserva `hostid`, `itemid`, `triggerid`, IDs de LLD etc.

Windows PowerShell:

```powershell
.\scripts\clone-db-to-z7.ps1
```

Linux/WSL:

```bash
./scripts/clone-db-to-z7.sh
```

Acompanhe o upgrade:

```powershell
docker compose --profile z7 logs -f zabbix-server7
```

Frontend Zabbix 7: http://localhost:8087

## 6. Fazer os itens pós-upgrade avançarem

Depois que o Zabbix 7 estiver disponível, envie valores para o server 7:

```powershell
python .\scripts\push-values.py --port 10071 --hosts 10 --synthetic-items 100
```

Isso faz o `lastclock` dos itens trapper ficar posterior ao baseline e permite observar a evolução do validator.

## 7. Apontar o validator para o Zabbix 7

Como o DB7 é uma cópia do DB6, usuários e configuração de API token também são clonados. Tente primeiro o mesmo token; se quiser gerar outro, use o script contra a porta 8087.

```env
NEW_ZABBIX_URL=http://host.docker.internal:8087/api_jsonrpc.php
NEW_ZABBIX_TOKEN=<token>
```

Recrie backend/worker do validator para ler o `.env` atualizado:

```powershell
docker compose up -d --force-recreate backend worker
```

## Testes de regressão sugeridos

Com a baseline congelada, altere **somente o Zabbix 7** e observe o validator:

- desabilite um item;
- altere um item para ficar unsupported;
- desabilite uma discovery rule;
- mude lifetime/Keep lost resources de uma LLD;
- remova ou altere um item prototype;
- altere o nome de um proxy mantendo o mesmo ID;
- desabilite Action/Media Type e marque como alteração esperada;
- pare o agent (`docker stop zbx-lab-agent6`) para observar interfaces/itens sem atualização;
- volte o agent (`docker start zbx-lab-agent6`) e veja a convergência.

## Escala

Comece pequeno. Exemplo de ~20 mil itens sintéticos:

```powershell
python .\scripts\seed-lab.py --hosts 20 --synthetic-items 1000
python .\scripts\push-values.py --port 10061 --hosts 20 --synthetic-items 1000
```

Não é necessário tentar reproduzir 3 milhões de itens no notebook para validar a lógica. O objetivo local é medir comportamento de lote, paralelismo, memória e tempos com volumes progressivos.

## Limpar tudo

```powershell
.\scripts\reset-lab.ps1
```
