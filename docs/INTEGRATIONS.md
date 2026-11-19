# Integrações de operações de segurança — v0.2.0

Esta versão acrescenta quatro fluxos defensivos. As integrações recebem inventário, relatórios e eventos; não iniciam scans, exploram sistemas ou executam resposta remota.

## 1. Descoberta autorizada de ativos

A API exige que um administrador registre um escopo com tipo `cidr`, `domain` ou `hostname`, referência de autorização formal e data de validade futura. Escopos vencidos/desativados não aceitam importação.

```bash
curl -X POST "$CTI/api/v1/discovery/scopes" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"scope_type":"cidr","value":"10.20.30.0/24","authorization_reference":"CHANGE-SEC-2026-010","valid_until":"2027-01-31T23:59:59Z"}'
```

A resposta inclui `id`; utilize-o para importar um lote (máximo 250 registros):

```bash
curl -X POST "$CTI/api/v1/discovery/import" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"scope_id":1,"source":"cmdb-export","assets":[{"name":"app01","hostname":"app01.corp.example","ip_address":"10.20.30.10","criticality":"high","environment":"production"}]}'
```

Cada registro precisa corresponder ao CIDR, hostname exato ou domínio aprovado. Um único registro fora do escopo rejeita o lote inteiro. A importação faz upsert por IP/hostname e registra auditoria. Desative escopos com `POST /api/v1/discovery/scopes/{id}/deactivate`. A função não faz descoberta por conexão, DNS brute force ou port scan.

## 2. Importação Trivy

Gere o JSON com Trivy no seu pipeline autorizado e envie o conteúdo para o ativo correspondente:

```bash
trivy image --format json --output trivy-report.json registry.example/app:1.2.3
```

```json
{
  "asset_id": 1,
  "report": {
    "Results": [{
      "Target": "registry.example/app:1.2.3",
      "Vulnerabilities": [{
        "VulnerabilityID": "CVE-2024-12345",
        "PkgName": "lib-example",
        "InstalledVersion": "1.0.0",
        "FixedVersion": "1.0.2",
        "Severity": "HIGH",
        "Title": "Example vulnerability",
        "CVSS": {"nvd": {"V3Score": 8.1}}
      }]
    }]
  }
}
```

`POST /api/v1/scanners/trivy/import` exige papel `admin` ou `analyst`. Apenas IDs no formato CVE são importados. A chave idempotente lógica é ativo + CVE; uma nova importação atualiza dados existentes em vez de criar duplicatas. O relatório possui limite de 8 MB.

## 3. Importação OpenVAS / Greenbone

Exporte o relatório XML a partir do Greenbone Vulnerability Management e envie `asset_id` + `report_xml` para `POST /api/v1/scanners/openvas/import`. O parser extrai CVEs, nome, descrição e CVSS. XML contendo DTD ou declaração ENTITY é recusado, assim como payloads acima de 8 MB. A API não se conecta ao Greenbone nem inicia tarefas de scan.

## 4. Integração SIEM (JSON e CEF)

### API autenticada

Um coletor ou adaptador pode normalizar alertas e publicar em `POST /api/v1/siem/events` usando JWT de uma conta `analyst` ou `admin`:

```json
{
  "source": "elastic-security",
  "external_id": "alert-000123",
  "event_type": "network.suspicious_connection",
  "severity": "high",
  "occurred_at": "2026-11-18T12:30:00Z",
  "source_ip": "203.0.113.77",
  "destination_ip": "10.20.30.10",
  "indicator_values": ["malicious.example"],
  "summary": "Conexão sinalizada pela regra de rede",
  "raw_event": {"rule_id": "network-402", "dataset": "firewall.alerts"}
}
```

`source` + `external_id` são únicos para deduplicação. O serviço correlaciona IPs com ativos, `indicator_values` com IOCs ativos e vulnerabilidades abertas/in-progress do ativo encontrado. `GET /api/v1/siem/events` e `GET /api/v1/siem/correlations` exibem o histórico.

### Webhook assinado

Configure um segredo forte e aleatório no servidor (mínimo 32 bytes):

```dotenv
SIEM_WEBHOOK_SECRET=COLOQUE_UM_SEGREDO_ALEATORIO_LONGO_AQUI
```

O remetente calcula HMAC-SHA256 sobre os bytes exatos do corpo e envia `X-CTI-Signature: sha256=<hex>`. O endpoint `/api/v1/siem/webhook` valida a assinatura em tempo constante. Aceita `application/json`, `text/plain` e `application/cef`, limita payload a 1 MB e recusa chamadas quando o segredo não está configurado.

Exemplo de assinatura em Python:

```python
import hashlib, hmac, requests
body = b'CEF:0|Vendor|Product|1.0|SIG-42|Suspicious login|8|src=203.0.113.77 msg=Failed logins'
signature = hmac.new(SIEM_WEBHOOK_SECRET.encode(), body, hashlib.sha256).hexdigest()
requests.post(
    f"{CTI_URL}/api/v1/siem/webhook",
    data=body,
    headers={"Content-Type": "application/cef", "X-CTI-Signature": f"sha256={signature}"},
    timeout=10,
)
```

O parser CEF lê o cabeçalho e os campos comuns `src`, `dst`, `msg` e `externalId`. Para integrações específicas de Splunk, Sentinel, Elastic ou QRadar, implemente um adaptador no coletor SIEM que mapeie os campos para o contrato normalizado acima, ou envie CEF com HMAC.

## 5. Motor de correlação e DeepSeek

A pontuação 0–100 é calculada pelo backend com base na severidade do evento, confiança dos IOCs, associação do ativo, vulnerabilidades abertas e presença de CVE no CISA KEV. A resposta inclui justificativas para que a equipe possa auditar a lógica. A escala é uma heurística inicial, não uma probabilidade estatística, não substitui regras do SIEM ou análise SOC e não deve disparar contenção automática.

`POST /api/v1/siem/correlations/{event_id}/analysis` envia um resumo mínimo do evento/correlação/IOCs/CVEs à DeepSeek. A IA é consultiva, não possui ferramentas de execução e não pode alterar ativos, casos ou infraestrutura.

## Limites operacionais

- Configure TLS, rate limiting e limites de tamanho no proxy de borda.
- Proteja `SIEM_WEBHOOK_SECRET` em secret manager e faça rotação periódica.
- Restrinja contas de serviço SIEM a `analyst` e revogue tokens quando necessário.
- Defina política de retenção para `raw_event`; não envie credenciais, dados pessoais desnecessários ou payloads proprietários à DeepSeek.
- Teste todos os mapeamentos do coletor SIEM em homologação antes da produção.
