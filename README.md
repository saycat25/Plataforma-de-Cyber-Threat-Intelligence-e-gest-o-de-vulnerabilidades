# Plataforma de Cyber Threat Intelligence e Gestão de Vulnerabilidades

Plataforma defensiva para centralizar ativos autorizados, vulnerabilidades, indicadores de comprometimento (IOCs), inteligência de ameaças, investigações e trilhas de auditoria. A DeepSeek funciona como camada assistiva de análise; decisões de prioridade são calculadas por regras determinísticas e evidências verificáveis.

> **Estado do projeto:** implementação inicial funcional (MVP técnico) com API, autenticação RBAC, persistência PostgreSQL/SQLite, integração CISA KEV/NVD, análise opcional DeepSeek, interface web, Docker e testes automatizados. Ainda requer hardening, testes de carga, revisão independente e implantação controlada antes de uso em produção crítica.

## Capacidades

- **Inventário de ativos:** criticidade, ambiente, responsável, exposição e tags.
- **Gestão de vulnerabilidades:** CVE, CVSS, EPSS, status, vínculo com ativos e priorização contextual.
- **Prioridade baseada em evidências:** pontuação reproduzível que considera CVSS, CISA KEV, EPSS, criticidade e exposição do ativo.
- **Threat Intelligence:** indicadores IPv4/IPv6, domínio, URL e hash, com classificação TLP e origem.
- **Feeds oficiais:** sincronização do CISA Known Exploited Vulnerabilities (KEV) e consulta individual ao NVD API 2.0.
- **Gestão de casos:** abertura, atribuição, estado, severidade e registro de investigação.
- **Auditoria:** trilha de eventos para ações de escrita e ingestão.
- **DeepSeek:** análise contextual opcional via API compatível com OpenAI, sem conceder à IA autoridade para executar ações.
- **Segurança:** JWT, Argon2id, papéis `admin`/`analyst`/`viewer`, CORS configurável, validação de entrada, limites de payload e headers de segurança.
- **Operação:** Docker Compose, migrações Alembic, health endpoint, CI e logs estruturados em formato JSON simples.

## Arquitetura

```text
React + TypeScript (Vite)
        │ Bearer JWT / REST
        ▼
FastAPI ── RBAC / validação / auditoria
   │            │
   │            ├── DeepSeek (análise assistiva opcional)
   │            ├── CISA KEV (feed JSON allowlisted)
   │            └── NVD API 2.0 (CVE sob demanda)
   ▼
Serviços de domínio
   ├── Risk Scoring determinístico
   ├── Asset & Vulnerability Management
   ├── IOC Lifecycle
   └── Case Management
        │
        ▼
PostgreSQL (produção) / SQLite (testes e desenvolvimento)
```

## Requisitos

- Python 3.11 ou superior (CI testa Python 3.11–3.13).
- Node.js 20 ou superior para a interface.
- Docker e Docker Compose (opcional, recomendado).
- Chave da DeepSeek apenas para habilitar análise por IA.

## Início rápido com Docker

1. Copie `.env.example` para `.env` e configure `SECRET_KEY` e as credenciais de bootstrap.
2. Defina uma senha forte para `BOOTSTRAP_ADMIN_PASSWORD` (mínimo de 14 caracteres recomendado).
3. Execute:

```bash
docker compose up --build
```

A API ficará em `http://localhost:8000`, a documentação OpenAPI em `http://localhost:8000/docs` e a interface em `http://localhost:5173`.

O utilizador administrador é criado automaticamente na inicialização da API apenas quando `BOOTSTRAP_ADMIN_EMAIL` e `BOOTSTRAP_ADMIN_PASSWORD` estão configurados. Não existe senha padrão embutida.

## Desenvolvimento local — Backend

```bash
cd backend
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate
pip install -e '.[dev]'
cp ../.env.example ../.env
# Configure DATABASE_URL=sqlite:///./cti.db no .env para desenvolvimento local
alembic upgrade head
python -m app.scripts.bootstrap_admin
uvicorn app.main:app --reload
```

Executar testes e lint:

```bash
pytest -q
ruff check app tests
```

## Desenvolvimento local — Frontend

```bash
cd frontend
npm install
npm run dev
```

Configure `VITE_API_BASE_URL=http://localhost:8000/api/v1` se necessário.

## Bootstrap do administrador

O bootstrap não usa credenciais fixas. Exemplo (Linux/macOS):

```bash
export BOOTSTRAP_ADMIN_EMAIL='admin@example.org'
export BOOTSTRAP_ADMIN_PASSWORD='use-uma-senha-forte-com-14-ou-mais-caracteres'
python -m app.scripts.bootstrap_admin
```

No Windows PowerShell, use `$env:BOOTSTRAP_ADMIN_EMAIL` e `$env:BOOTSTRAP_ADMIN_PASSWORD`.

## API principal

| Método | Endpoint | Acesso | Descrição |
|---|---|---|---|
| `GET` | `/health` | Público | Health check |
| `POST` | `/api/v1/auth/token` | Público | Login OAuth2 password form |
| `GET/POST` | `/api/v1/assets` | Autenticado / analyst+ | Inventário de ativos |
| `GET/POST` | `/api/v1/vulnerabilities` | Autenticado / analyst+ | Gestão de CVEs |
| `PATCH` | `/api/v1/vulnerabilities/{id}` | analyst+ | Atualizar estado/atribuição |
| `GET/POST` | `/api/v1/indicators` | Autenticado / analyst+ | Indicadores de ameaça |
| `GET/POST/PATCH` | `/api/v1/cases` | Autenticado / analyst+ | Investigações |
| `POST` | `/api/v1/intelligence/feeds/cisa-kev/sync` | admin | Sincronizar catálogo CISA KEV |
| `POST` | `/api/v1/intelligence/feeds/nvd/{cve_id}/sync` | admin | Consultar NVD para um CVE |
| `POST` | `/api/v1/intelligence/analysis` | analyst+ | Análise contextual DeepSeek |
| `GET` | `/api/v1/dashboard/summary` | Autenticado | Indicadores de operação |
| `GET` | `/api/v1/audit/events` | admin | Eventos de auditoria |
| `GET/POST` | `/api/v1/users` | admin | Administração de usuários e papéis |
| `PATCH` | `/api/v1/assets/{id}` | analyst+ | Atualizar metadados do ativo |
| `PATCH` | `/api/v1/indicators/{id}` | analyst+ | Atualizar confiança, TLP ou estado |

## Priorização de vulnerabilidades

O `risk_score` (0–100) é calculado pela aplicação, não pelo LLM:

- CVSS: até 40 pontos (normalizado de 0–10).
- CISA KEV: 25 pontos quando a exploração está confirmada no catálogo.
- EPSS: até 15 pontos (percentil/probabilidade 0–1).
- Criticidade do ativo: até 10 pontos.
- Exposição à Internet: até 10 pontos.

Faixas: `critical` ≥ 80; `high` ≥ 60; `medium` ≥ 35; caso contrário `low`. A fórmula é uma heurística operacional configurável, não substitui avaliação de risco formal, contexto de negócio ou validação humana.

## Integração DeepSeek

Configure `DEEPSEEK_API_KEY` e opcionalmente `DEEPSEEK_MODEL=deepseek-flash` ou `deepseek-v4-pro`. O serviço usa `https://api.deepseek.com/chat/completions`. Sem chave, os endpoints centrais continuam funcionais e a análise de IA retorna `503`.

A IA recebe apenas um resumo técnico mínimo de ativos, CVEs e IOCs selecionados. Evidências são tratadas como dados não confiáveis; a resposta é consultiva, não executa comandos, não altera ativos e não aprova remediações.

Documentação: https://api-docs.deepseek.com/ e https://api-docs.deepseek.com/api/create-chat-completion/.

## Feeds e proveniência

- **CISA KEV:** `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`.
- **NVD:** `https://services.nvd.nist.gov/rest/json/cves/2.0`.

A sincronização KEV consulta apenas o endpoint fixo do CISA; não aceita URL fornecida pelo usuário, reduzindo risco de SSRF. Os dados externos preservam origem e data de ingestão. Configure `NVD_API_KEY` para aumentar limites de requisição, conforme as regras do NVD.

## Segurança e uso autorizado

Esta plataforma é uma ferramenta defensiva. A versão incluída **não implementa exploração, brute force, varredura ativa ou execução remota**. O inventário deve conter somente ativos próprios ou explicitamente autorizados. Integrações futuras com scanners devem importar resultados de ferramentas aprovadas e manter escopo, autorização e trilha de auditoria.

Antes de produção:

1. Troque todos os segredos, use um gestor de segredos e TLS.
2. Configure CORS com origens exatas, proxy confiável e rate limiting externo.
3. Use PostgreSQL gerenciado, backups, PITR e restauração testada.
4. Aplique migrações em pipeline controlado e execute testes de segurança.
5. Configure retenção, classificação e minimização de dados.
6. Faça threat modeling, pentest autorizado, teste de carga e revisão de código independente.
7. Implemente SIEM/observabilidade e alertas para acessos e operações privilegiadas.

Consulte `docs/SECURITY.md`, `docs/THREAT_MODEL.md` e `docs/OPERATIONS.md`.

## Pacote de distribuição

O pacote compactado desta versão também está disponível em [`dist/cti-platform-0.1.0.tar.gz`](dist/cti-platform-0.1.0.tar.gz). Confira a integridade pelo arquivo [`SHA256SUMS`](SHA256SUMS).

## Licença

MIT. Consulte `LICENSE`.
