# API — autenticação e integrações v0.2.0

Autenticação de usuário usa OAuth2 password form e token Bearer.

```bash
curl -X POST http://localhost:8000/api/v1/auth/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'username=admin@example.org' \
  --data-urlencode 'password=SUA_SENHA'
```

## Descoberta autorizada

Apenas administradores podem criar/desativar escopos. Importação de registros é permitida a `admin` e `analyst`, mas cada hostname/IP precisa estar no escopo ativo e não expirado. A rota é de importação passiva; não abre conexões para descobrir hosts.

```http
POST /api/v1/discovery/scopes
POST /api/v1/discovery/import
POST /api/v1/discovery/scopes/{scope_id}/deactivate
```

A referência de autorização e a validade são persistidas. Lotes fora de escopo são rejeitados integralmente.

## Importação de scanners

```http
POST /api/v1/scanners/trivy/import
POST /api/v1/scanners/openvas/import
```

Trivy recebe `{ "asset_id": 1, "report": { ... } }` com JSON do Trivy. OpenVAS/GVM recebe `{ "asset_id": 1, "report_xml": "<report>...</report>" }`. Os ativos devem existir; somente CVEs reconhecidas são persistidas; importações repetidas atualizam o registro do par ativo/CVE.

## SIEM e correlação

```http
POST /api/v1/siem/events
GET  /api/v1/siem/events
GET  /api/v1/siem/correlations
POST /api/v1/siem/correlations/{event_id}/analysis
POST /api/v1/siem/webhook
```

A API autenticada requer `admin` ou `analyst`. O webhook não usa JWT, mas exige HMAC-SHA256 no cabeçalho `X-CTI-Signature` e `SIEM_WEBHOOK_SECRET` configurado; aceita JSON normalizado ou CEF.

O contrato JSON inclui `source`, `external_id`, `event_type`, `severity`, `summary` e campos opcionais `occurred_at`, `source_ip`, `destination_ip`, `indicator_values`, `raw_event`. A deduplicação usa origem + ID externo. A correlação é heurística auditável e não produz contenção automática.

## DeepSeek

O endpoint `POST /api/v1/intelligence/analysis` aceita pergunta e IDs de vulnerabilidades/indicadores. A rota `POST /api/v1/siem/correlations/{event_id}/analysis` resume a evidência correlacionada. Ambas requerem `admin` ou `analyst` e chave DeepSeek configurada. Respostas são consultivas; dados externos e logs são considerados não confiáveis.

Consulte `docs/INTEGRATIONS.md` para exemplos completos, formatos e configuração do webhook.
