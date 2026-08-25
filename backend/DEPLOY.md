# Publicacao da API - Portal Pre-Vendas NDD

## Pre-requisitos

A hospedagem precisa executar Node.js 20+ e conseguir abrir conexao TCP com o MSSQL.

## Banco

1. Execute `database/001_auth_auditoria.sql` no MSSQL.
2. Confirme a existencia das tabelas `portal_users`, `portal_sessions`, `portal_login_log`, `portal_action_log` e `portal_generated_documents`.

## API

Configure no ambiente da hospedagem, sem gravar valores reais no GitHub:

- `MSSQL_SERVER`
- `MSSQL_PORT`
- `MSSQL_DATABASE`
- `MSSQL_USER`
- `MSSQL_PASSWORD`
- `MSSQL_ENCRYPT`
- `MSSQL_TRUST_CERT`
- `SESSION_SECRET`
- `SESSION_HOURS`
- `ALLOWED_ORIGIN`

Instalacao/start:

```bash
cd backend
npm install
npm start
```

Teste inicial: `GET /health` deve responder JSON com `ok: true`.

## Primeiro administrador

Com as variaveis de ambiente configuradas:

```bash
npm run create-admin -- admin "Administrador NDD" "SENHA-INICIAL-FORTE" admin@empresa.com
```

A senha e transformada em bcrypt antes de ser armazenada. O script tambem pode reativar/promover um usuario existente para ADMIN.

## Frontend

Depois que a API tiver uma URL HTTPS definitiva, alterar apenas `auth/config.js`, preenchendo `apiBaseUrl` com essa URL.

## Validacao obrigatoria antes da main

1. `/health` conectado ao MSSQL.
2. Login ADMIN valido e login invalido registrado.
3. `/auth/me` retorna o usuario correto.
4. ADMIN cria um USER.
5. USER nao acessa endpoints `/admin/*`.
6. Logout revoga a sessao.
7. Auditoria grava uma acao e um documento.
8. Historico ADMIN retorna login, acoes e documentos.
9. Somente depois integrar/proteger todas as paginas existentes.
10. Somente depois abrir PR para `main`.
