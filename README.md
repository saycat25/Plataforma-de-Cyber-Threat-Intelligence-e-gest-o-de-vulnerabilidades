# Plataforma de Cyber Threat Intelligence e Gestão de Vulnerabilidades

Plataforma defensiva para inventário de ativos autorizados, gestão e priorização contextual de vulnerabilidades, indicadores de comprometimento (IOCs), threat intelligence, casos de investigação e auditoria.

## Distribuição do código-fonte

O pacote completo desta versão está em **[dist/cti-platform-0.1.0.tar.gz](dist/cti-platform-0.1.0.tar.gz)**. Ele inclui backend FastAPI, frontend React/TypeScript, migrações Alembic, testes, Docker Compose, CI e documentação técnica em português.

## Capacidades incluídas

- API FastAPI com JWT, Argon2id e RBAC (admin, analyst, viewer).
- Inventário de ativos e gestão de vulnerabilidades CVE.
- Priorização determinística baseada em CVSS, CISA KEV, EPSS, criticidade e exposição.
- Gestão e normalização de IOCs (IPv4/IPv6, domínios, URLs e hashes) com TLP e confiança.
- Gestão de casos e eventos de auditoria.
- Ingestão do CISA Known Exploited Vulnerabilities (KEV) e consulta ao NVD API 2.0.
- Análise assistiva opcional via DeepSeek (deepseek-flash ou deepseek-v4-pro).
- Interface web React + TypeScript, PostgreSQL, Docker Compose e GitHub Actions.

## Executar

1. Baixe e extraia dist/cti-platform-0.1.0.tar.gz.
2. Entre na pasta cti-platform/.
3. Copie .env.example para .env e substitua os segredos de exemplo.
4. Configure BOOTSTRAP_ADMIN_EMAIL e uma BOOTSTRAP_ADMIN_PASSWORD forte.
5. Execute docker compose up --build.

API: http://localhost:8000 · OpenAPI: http://localhost:8000/docs · Web: http://localhost:5173

## Qualidade e limites

Os testes backend incluídos foram executados localmente: **11 passaram**. A migração inicial foi validada em SQLite e os módulos Python compilaram. A instalação do Ruff e das dependências npm não pôde ser feita neste ambiente sem acesso ao registry de pacotes; portanto lint e build frontend ainda precisam ser executados em CI.

Esta é a versão inicial funcional (MVP técnico), não uma certificação de produção. Antes de uso crítico, faça revisão independente, hardening, MFA/SSO, rate limiting, teste de carga, pentest autorizado, gestão de segredos, backups e implantação monitorada.

**Uso exclusivamente defensivo:** cadastre somente ativos próprios ou com autorização explícita. Não há exploração automática, brute force, varredura ativa ou execução remota. A DeepSeek fornece análise consultiva e não executa ações.

Documentação detalhada, threat model, operação e segurança estão dentro do pacote em docs/.

Licença: MIT.
