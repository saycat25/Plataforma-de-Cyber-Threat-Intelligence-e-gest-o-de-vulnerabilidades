# Segurança e operação segura

## Controles implementados

- JWT assinado com chave configurável e expiração limitada.
- Hash de senha Argon2id.
- Papéis `admin`, `analyst` e `viewer`.
- Validação de payload por Pydantic e limites de tamanho.
- CORS por allowlist.
- Headers `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy` e `Permissions-Policy`.
- Não há endpoint de execução de comandos nem scanner ativo.
- Integrações externas usam endpoints fixos, timeout e sem redirects.
- A integração DeepSeek envia evidências mínimas e trata conteúdo de feed como dado não confiável.

## Controles obrigatórios antes de produção

- Secret manager e rotação de chaves; não reutilizar `SECRET_KEY` de desenvolvimento.
- HTTPS atrás de proxy configurado corretamente e HSTS no ingress.
- Rate limiting por usuário/IP no gateway/WAF.
- MFA e SSO corporativo.
- Política de senha, recuperação segura e revogação/rotação de tokens.
- Criptografia em repouso, backups cifrados e teste de restauração.
- Testes DAST/SAST/SCA, pentest autorizado e revisão de dependências.
- Retenção de logs, proteção contra alteração e exportação para SIEM.
- Política de privacidade e classificação de dados.
- Proteção CSRF caso a autenticação seja migrada para cookies.

## Modelo de confiança da IA

A resposta DeepSeek nunca deve ser tratada como evidência ou decisão final. Não fornecemos tool calling nem acesso de escrita ao modelo. O analista deve verificar recomendações em fontes oficiais e seguir runbooks aprovados. Não envie segredos, dados pessoais ou conteúdo restrito para o provedor sem autorização e revisão contratual.

## Escopo autorizado

Cadastre apenas sistemas próprios ou com autorização explícita. A versão atual é passiva: importa catálogos de vulnerabilidades e registra inventário fornecido por operadores. Nenhuma função realiza exploração, brute force, evasão, varredura ativa ou alteração de sistemas monitorados.
