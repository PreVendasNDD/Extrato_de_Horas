'use strict';

require('dotenv').config();
const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const sql = require('mssql');

const required = ['MSSQL_SERVER','MSSQL_DATABASE','MSSQL_USER','MSSQL_PASSWORD','SESSION_SECRET','ALLOWED_ORIGIN'];
for (const name of required) {
  if (!process.env[name]) throw new Error(`Variavel obrigatoria ausente: ${name}`);
}

const dbConfig = {
  server: process.env.MSSQL_SERVER,
  port: Number(process.env.MSSQL_PORT || 1433),
  database: process.env.MSSQL_DATABASE,
  user: process.env.MSSQL_USER,
  password: process.env.MSSQL_PASSWORD,
  options: {
    encrypt: process.env.MSSQL_ENCRYPT !== 'false',
    trustServerCertificate: process.env.MSSQL_TRUST_CERT === 'true'
  },
  pool: { max: 10, min: 0, idleTimeoutMillis: 30000 }
};

const app = express();
app.set('trust proxy', 1);
app.use(helmet());
app.use(cors({ origin: process.env.ALLOWED_ORIGIN.split(',').map(v => v.trim()), credentials: false }));
app.use(express.json({ limit: '2mb' }));

let pool;
const sha256 = value => crypto.createHash('sha256').update(value).digest('hex');
const randomToken = () => crypto.randomBytes(48).toString('base64url');
const ipOf = req => String(req.ip || req.socket.remoteAddress || '').slice(0, 64);
const uaOf = req => String(req.get('user-agent') || '').slice(0, 1000);

async function db() {
  if (!pool) pool = await sql.connect(dbConfig);
  return pool;
}

async function auth(req, res, next) {
  try {
    const header = String(req.get('authorization') || '');
    if (!header.startsWith('Bearer ')) return res.status(401).json({ error: 'NAO_AUTENTICADO' });
    const token = header.slice(7).trim();
    if (!token) return res.status(401).json({ error: 'NAO_AUTENTICADO' });
    const p = await db();
    const result = await p.request()
      .input('hash', sql.Char(64), sha256(token))
      .query(`SELECT TOP 1 u.id,u.username,u.display_name,u.email,u.role
              FROM dbo.portal_sessions s
              JOIN dbo.portal_users u ON u.id=s.user_id
              WHERE s.token_hash=@hash AND s.revoked_at IS NULL
                AND s.expires_at>SYSUTCDATETIME() AND u.is_active=1`);
    if (!result.recordset.length) return res.status(401).json({ error: 'SESSAO_INVALIDA' });
    req.user = result.recordset[0];
    req.sessionTokenHash = sha256(token);
    next();
  } catch (err) { next(err); }
}

function admin(req, res, next) {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ error: 'ACESSO_NEGADO' });
  next();
}

app.get('/health', async (_req, res, next) => {
  try {
    const p = await db();
    await p.request().query('SELECT 1 AS ok');
    res.json({ ok: true, service: 'ndd-prevendas-api' });
  } catch (err) { next(err); }
});

app.post('/auth/login', async (req, res, next) => {
  try {
    const username = String(req.body.username || '').trim();
    const password = String(req.body.password || '');
    if (!username || !password) return res.status(400).json({ error: 'USUARIO_E_SENHA_OBRIGATORIOS' });
    const p = await db();
    const found = await p.request().input('username', sql.NVarChar(120), username)
      .query('SELECT TOP 1 id,username,display_name,email,password_hash,role,is_active FROM dbo.portal_users WHERE username=@username');
    const user = found.recordset[0];
    const success = Boolean(user && user.is_active && await bcrypt.compare(password, user.password_hash));
    await p.request()
      .input('user_id', sql.BigInt, user ? user.id : null)
      .input('username', sql.NVarChar(120), username)
      .input('success', sql.Bit, success)
      .input('ip', sql.NVarChar(64), ipOf(req))
      .input('ua', sql.NVarChar(1000), uaOf(req))
      .input('reason', sql.NVarChar(255), success ? null : 'Credenciais invalidas ou usuario inativo')
      .query('INSERT INTO dbo.portal_login_log(user_id,username_attempted,success,ip_address,user_agent,failure_reason) VALUES(@user_id,@username,@success,@ip,@ua,@reason)');
    if (!success) return res.status(401).json({ error: 'CREDENCIAIS_INVALIDAS' });
    const token = randomToken();
    const sessionId = crypto.randomUUID();
    const hours = Number(process.env.SESSION_HOURS || 12);
    await p.request()
      .input('id', sql.UniqueIdentifier, sessionId)
      .input('uid', sql.BigInt, user.id)
      .input('hash', sql.Char(64), sha256(token))
      .input('hours', sql.Int, hours)
      .input('ip', sql.NVarChar(64), ipOf(req))
      .input('ua', sql.NVarChar(1000), uaOf(req))
      .query(`INSERT INTO dbo.portal_sessions(id,user_id,token_hash,expires_at,ip_address,user_agent)
              VALUES(@id,@uid,@hash,DATEADD(HOUR,@hours,SYSUTCDATETIME()),@ip,@ua);
              UPDATE dbo.portal_users SET last_login_at=SYSUTCDATETIME(),updated_at=SYSUTCDATETIME() WHERE id=@uid`);
    res.json({ token, expiresInHours: hours, user: { id:user.id, username:user.username, displayName:user.display_name, email:user.email, role:user.role } });
  } catch (err) { next(err); }
});

app.post('/auth/logout', auth, async (req, res, next) => {
  try {
    const p = await db();
    await p.request().input('hash', sql.Char(64), req.sessionTokenHash)
      .query('UPDATE dbo.portal_sessions SET revoked_at=SYSUTCDATETIME() WHERE token_hash=@hash AND revoked_at IS NULL');
    res.json({ ok: true });
  } catch (err) { next(err); }
});

app.get('/auth/me', auth, (req, res) => res.json({ user: req.user }));

app.post('/audit/actions', auth, async (req, res, next) => {
  try {
    const b = req.body || {};
    if (!b.actionType) return res.status(400).json({ error: 'ACTION_TYPE_OBRIGATORIO' });
    const p = await db();
    const r = await p.request()
      .input('uid', sql.BigInt, req.user.id)
      .input('action', sql.NVarChar(80), String(b.actionType).slice(0,80))
      .input('product', sql.NVarChar(40), b.product ? String(b.product).slice(0,40) : null)
      .input('client', sql.NVarChar(255), b.clientName ? String(b.clientName).slice(0,255) : null)
      .input('document', sql.NVarChar(1000), b.clientDocument ? String(b.clientDocument).slice(0,1000) : null)
      .input('payload', sql.NVarChar(sql.MAX), b.payload == null ? null : JSON.stringify(b.payload))
      .input('result', sql.NVarChar(sql.MAX), b.result == null ? null : JSON.stringify(b.result))
      .input('page', sql.NVarChar(500), b.pagePath ? String(b.pagePath).slice(0,500) : null)
      .input('ip', sql.NVarChar(64), ipOf(req))
      .query(`INSERT INTO dbo.portal_action_log(user_id,action_type,product,client_name,client_document,payload_json,result_json,page_path,ip_address)
              OUTPUT INSERTED.id VALUES(@uid,@action,@product,@client,@document,@payload,@result,@page,@ip)`);
    res.status(201).json({ id: r.recordset[0].id });
  } catch (err) { next(err); }
});

app.post('/audit/documents', auth, async (req, res, next) => {
  try {
    const b = req.body || {};
    if (!['EXTRATO','PROPOSTA'].includes(b.documentType) || !b.product || b.snapshot == null)
      return res.status(400).json({ error: 'DOCUMENTO_INVALIDO' });
    const p = await db();
    const r = await p.request()
      .input('uid', sql.BigInt, req.user.id)
      .input('actionId', sql.BigInt, b.actionLogId || null)
      .input('type', sql.NVarChar(40), b.documentType)
      .input('product', sql.NVarChar(40), String(b.product).slice(0,40))
      .input('client', sql.NVarChar(255), b.clientName ? String(b.clientName).slice(0,255) : null)
      .input('snapshot', sql.NVarChar(sql.MAX), JSON.stringify(b.snapshot))
      .query(`INSERT INTO dbo.portal_generated_documents(user_id,action_log_id,document_type,product,client_name,snapshot_json)
              OUTPUT INSERTED.id VALUES(@uid,@actionId,@type,@product,@client,@snapshot)`);
    res.status(201).json({ id: r.recordset[0].id });
  } catch (err) { next(err); }
});

app.get('/admin/users', auth, admin, async (_req, res, next) => {
  try {
    const p = await db();
    const r = await p.request().query('SELECT id,username,display_name,email,role,is_active,created_at,updated_at,last_login_at FROM dbo.portal_users ORDER BY display_name');
    res.json({ users: r.recordset });
  } catch (err) { next(err); }
});

app.post('/admin/users', auth, admin, async (req, res, next) => {
  try {
    const b = req.body || {};
    if (!b.username || !b.displayName || !b.password || !['ADMIN','USER'].includes(b.role || 'USER'))
      return res.status(400).json({ error: 'DADOS_DE_USUARIO_INVALIDOS' });
    const hash = await bcrypt.hash(String(b.password), 12);
    const p = await db();
    const r = await p.request()
      .input('username', sql.NVarChar(120), String(b.username).trim())
      .input('name', sql.NVarChar(180), String(b.displayName).trim())
      .input('email', sql.NVarChar(255), b.email ? String(b.email).trim() : null)
      .input('hash', sql.NVarChar(255), hash)
      .input('role', sql.NVarChar(20), b.role || 'USER')
      .query(`INSERT INTO dbo.portal_users(username,display_name,email,password_hash,role)
              OUTPUT INSERTED.id VALUES(@username,@name,@email,@hash,@role)`);
    res.status(201).json({ id: r.recordset[0].id });
  } catch (err) { next(err); }
});

app.patch('/admin/users/:id', auth, admin, async (req, res, next) => {
  try {
    const id = Number(req.params.id); const b = req.body || {};
    if (!Number.isSafeInteger(id) || id <= 0) return res.status(400).json({ error: 'ID_INVALIDO' });
    if (b.role != null && !['ADMIN','USER'].includes(b.role)) return res.status(400).json({ error: 'PERFIL_INVALIDO' });
    const p = await db();
    await p.request()
      .input('id', sql.BigInt, id)
      .input('name', sql.NVarChar(180), b.displayName == null ? null : String(b.displayName).trim())
      .input('email', sql.NVarChar(255), b.email == null ? null : String(b.email).trim())
      .input('role', sql.NVarChar(20), b.role == null ? null : b.role)
      .input('active', sql.Bit, b.isActive == null ? null : Boolean(b.isActive))
      .query(`UPDATE dbo.portal_users SET
              display_name=COALESCE(@name,display_name), email=COALESCE(@email,email),
              role=COALESCE(@role,role), is_active=COALESCE(@active,is_active), updated_at=SYSUTCDATETIME()
              WHERE id=@id`);
    if (b.password) {
      const hash = await bcrypt.hash(String(b.password), 12);
      await p.request().input('id', sql.BigInt, id).input('hash', sql.NVarChar(255), hash)
        .query('UPDATE dbo.portal_users SET password_hash=@hash,updated_at=SYSUTCDATETIME() WHERE id=@id; UPDATE dbo.portal_sessions SET revoked_at=SYSUTCDATETIME() WHERE user_id=@id AND revoked_at IS NULL');
    }
    res.json({ ok: true });
  } catch (err) { next(err); }
});

app.get('/admin/users/:id/history', auth, admin, async (req, res, next) => {
  try {
    const id = Number(req.params.id); if (!Number.isSafeInteger(id)) return res.status(400).json({ error: 'ID_INVALIDO' });
    const p = await db();
    const logins = await p.request().input('id', sql.BigInt, id).query('SELECT TOP 200 id,success,occurred_at,ip_address,failure_reason FROM dbo.portal_login_log WHERE user_id=@id ORDER BY occurred_at DESC');
    const actions = await p.request().input('id', sql.BigInt, id).query('SELECT TOP 500 id,action_type,product,client_name,client_document,payload_json,result_json,page_path,occurred_at FROM dbo.portal_action_log WHERE user_id=@id ORDER BY occurred_at DESC');
    const documents = await p.request().input('id', sql.BigInt, id).query('SELECT TOP 500 id,document_type,product,client_name,snapshot_json,generated_at FROM dbo.portal_generated_documents WHERE user_id=@id ORDER BY generated_at DESC');
    res.json({ logins: logins.recordset, actions: actions.recordset, documents: documents.recordset });
  } catch (err) { next(err); }
});

app.use((err, _req, res, _next) => {
  console.error(err);
  const duplicate = err && err.number === 2627;
  res.status(duplicate ? 409 : 500).json({ error: duplicate ? 'REGISTRO_DUPLICADO' : 'ERRO_INTERNO' });
});

const port = Number(process.env.PORT || 3000);
app.listen(port, async () => {
  await db();
  console.log(`NDD Pre-Vendas API ativa na porta ${port}`);
});
