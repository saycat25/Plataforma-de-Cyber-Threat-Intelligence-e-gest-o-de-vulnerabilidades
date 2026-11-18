# API — exemplos

Autenticação usa OAuth2 password form e token Bearer.

```bash
curl -X POST http://localhost:8000/api/v1/auth/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'username=admin@example.org' \
  --data-urlencode 'password=SUA_SENHA'
```

Cadastre ativo autorizado:

```bash
curl -X POST http://localhost:8000/api/v1/assets \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"ERP Produção","criticality":"critical","environment":"production","internet_exposed":true}'
```

Sincronize KEV (admin):

```bash
curl -X POST http://localhost:8000/api/v1/intelligence/feeds/cisa-kev/sync \
  -H "Authorization: Bearer $TOKEN"
```

Solicite análise assistiva:

```json
{
  "question": "Resuma a prioridade e os próximos passos defensivos para os itens selecionados.",
  "vulnerability_ids": [1],
  "indicator_ids": [2]
}
```

Endpoint: `POST /api/v1/intelligence/analysis`. Requer papel `admin` ou `analyst` e chave DeepSeek configurada.
