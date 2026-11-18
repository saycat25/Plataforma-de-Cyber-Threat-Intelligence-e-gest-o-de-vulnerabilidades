# Arquitetura técnica

## Objetivos

A arquitetura separa ingestão, domínio, análise e apresentação. A API mantém a autoridade sobre validação, autorização, persistência e cálculo de risco. Modelos de linguagem são serviços externos não confiáveis e não recebem ferramentas com privilégios de execução nesta versão.

## Contextos de domínio

- **Asset Management:** inventário de ativos autorizados, atributos de negócio e exposição.
- **Vulnerability Management:** registro de CVEs, fontes, CVSS, EPSS, KEV e ciclo de tratamento.
- **Threat Intelligence:** normalização, confiança, TLP, origem e observação de IOCs.
- **Incident Management:** casos, atribuição, severidade, estado e resolução.
- **Governance:** RBAC e eventos de auditoria.
- **AI Assist:** análise contextual sob demanda, com payload mínimo e sem side effects.

## Persistência

PostgreSQL é o destino de produção. SQLAlchemy 2 isola o modelo de domínio do dialeto; Alembic versiona o schema. SQLite é usado nos testes. Em ambiente maior, eventos de ingestão e atualizações podem ser movidos para Kafka e workers independentes; essa infraestrutura distribuída não é simulada na versão atual.

## Ingestão

CISA KEV é consultado por URL fixa allowlisted. NVD é consultado para um CVE por requisição. Ambos os conectores têm timeout, não seguem redirects e não aceitam URLs arbitrárias fornecidas pelo usuário. Dados externos são validados e armazenados com identificação da fonte.

## Prioridade contextual

O score 0–100 é calculado em `app/services/risk.py`: CVSS (40), KEV (25), EPSS (15), criticidade (10), exposição pública (10). O score auxilia triagem e pode ser calibrado pela organização. O cálculo deve ser versionado ao evoluir para suportar recalculação histórica.

## Próximos passos de escala

1. Outbox transacional e workers idempotentes para ingestão.
2. Kafka para fan-out de eventos e back-pressure.
3. OpenSearch para consulta de IOCs e evidências em escala.
4. Neo4j para relações entre entidades e campanhas, com proveniência.
5. Object storage com retenção e hash de integridade para evidências.
6. Multi-tenancy com isolamento por tenant no banco e nas filas.
7. SSO OIDC/SAML, SCIM e MFA.
