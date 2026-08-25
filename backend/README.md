# API Portal Pre-Vendas NDD

Esta pasta recebera a API responsavel por autenticacao, autorizacao, MSSQL e auditoria.

## Regra de seguranca

Credenciais MSSQL, segredos de sessao e demais chaves **nunca** devem ser gravados neste repositorio ou enviados ao frontend do GitHub Pages.

## Responsabilidades da API

- login/logout e validacao de sessao;
- perfis `ADMIN` e `USER`;
- CRUD administrativo de usuarios;
- registro de tentativas de login;
- registro de acoes executadas no portal;
- snapshots de extratos e propostas gerados;
- consultas de historico para o painel administrativo.

## Variaveis de ambiente previstas

- `MSSQL_SERVER`
- `MSSQL_PORT`
- `MSSQL_DATABASE`
- `MSSQL_USER`
- `MSSQL_PASSWORD`
- `SESSION_SECRET`
- `ALLOWED_ORIGIN`

Os valores reais devem existir apenas no ambiente onde a API estiver hospedada.
