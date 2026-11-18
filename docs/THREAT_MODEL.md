# Threat model (resumo)

## Ativos a proteger

Credenciais, tokens, inventário interno, indicadores restritos por TLP, evidências de incidentes, decisões de risco e integridade dos eventos de auditoria.

## Atores e ameaças

| Ameaça | Mitigação atual | Lacuna / ação futura |
|---|---|---|
| Roubo de senha | Argon2id + JWT curto | MFA, SSO, revogação de sessão e detecção de credential stuffing |
| Escalada de privilégio | RBAC por dependência | Testes formais de autorização em todos os endpoints e revisão por tenant |
| SSRF via feed | URLs fixas, sem redirect | Egress firewall e proxy de saída |
| Prompt injection em evidência | Delimitação como dado não confiável; sem ferramentas | Avaliação adversarial contínua e filtros de saída |
| Abuso de endpoint | Limites de paginação e payload | Rate limiting centralizado e quotas |
| Alteração de auditoria | Eventos append-only na API | Permissões DB restritas, armazenamento externo WORM e assinatura |
| Exposição de segredos | `.env` ignorado pelo Git | Secret manager, scanner de secrets e rotação |
| CVE/IOC malformado | Pydantic + normalizadores | Schemas de feed versionados e quarentena de dados |

## Limites de confiança

- Usuários autenticados ainda são entradas não confiáveis.
- Feeds públicos e seus campos textuais são dados não confiáveis.
- Saídas de LLM são sugestões não verificadas.
- O banco é confiável apenas sob credenciais de serviço protegidas e backups verificados.

## Critérios de release

Não promover para produção crítica sem threat modeling específico da implantação, revisão de RBAC, varredura de dependências, testes de API, DAST, teste de restauração de backup e aceite formal do proprietário do risco.
