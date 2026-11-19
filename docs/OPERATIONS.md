# Operação

## Inicialização

- Configure `.env` fora do controle de versão.
- Use `SECRET_KEY` aleatória com pelo menos 32 bytes.
- Defina senha de bootstrap forte e remova-a do ambiente após a criação inicial do administrador.
- Execute `alembic upgrade head`.
- Verifique `GET /health` e `GET /docs` (docs apenas fora de produção).

## Ingestão de feeds

- CISA KEV: `POST /api/v1/intelligence/feeds/cisa-kev/sync` (admin).
- NVD: `POST /api/v1/intelligence/feeds/nvd/{CVE-ID}/sync` (admin).
- Programe a sincronização KEV em um scheduler externo com intervalo adequado e alertas para falhas. Não crie concorrência ilimitada.
- A chave NVD é opcional e deve ser obtida e armazenada conforme as instruções do NVD.

## Backup e recuperação

- Faça backups consistentes de PostgreSQL e teste restauração.
- Defina RPO/RTO com o proprietário do serviço.
- Preserve evidências e eventos de auditoria segundo política de retenção.

## Observabilidade

A API emite logs de requisição com status, duração e request ID. Não registra corpos, tokens ou senhas. Em produção, encaminhe logs para sistema centralizado, adicione métricas RED, tracing e alertas de feed/login/erros.

## Diagnóstico

- `503` em análise: falta `DEEPSEEK_API_KEY` ou serviço indisponível.
- `502` na ingestão: fonte externa indisponível ou feed inválido; consulte logs e `feed_runs`.
- `401`: token ausente/inválido/expirado.
- `403`: papel sem permissão.


## Integrações v0.2.0

- `SIEM_WEBHOOK_SECRET`: segredo aleatório forte para webhook HMAC-SHA256. Quando ausente, `/api/v1/siem/webhook` retorna 503; prefira o secret manager em produção.
- Descoberta: criar escopo aprovado antes de importar CMDB/inventário; desativar imediatamente quando a autorização vencer ou for revogada. Escopos novos expiram em data explícita.
- Scanners: exportar Trivy JSON ou OpenVAS XML no pipeline controlado e associar explicitamente ao `asset_id`; não enviar relatório para ativo incorreto.
- SIEM: usar uma conta técnica de papel `analyst` para API JWT; para webhook, assinar os bytes exatos do corpo. Configurar TLS e allowlist de origem no proxy.
- Monitorar falhas `401`, `403`, `413`, `422` e `503` nos endpoints de integração.
