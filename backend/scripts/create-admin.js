'use strict';
require('dotenv').config();
const bcrypt = require('bcryptjs');
const sql = require('mssql');

const username = process.argv[2];
const displayName = process.argv[3];
const password = process.argv[4];
const email = process.argv[5] || null;
if (!username || !displayName || !password) {
  console.error('Uso: npm run create-admin -- <usuario> "<nome>" <senha> [email]');
  process.exit(1);
}
if (password.length < 10) {
  console.error('A senha inicial deve ter pelo menos 10 caracteres.');
  process.exit(1);
}
const config={server:process.env.MSSQL_SERVER,port:Number(process.env.MSSQL_PORT||1433),database:process.env.MSSQL_DATABASE,user:process.env.MSSQL_USER,password:process.env.MSSQL_PASSWORD,options:{encrypt:process.env.MSSQL_ENCRYPT!=='false',trustServerCertificate:process.env.MSSQL_TRUST_CERT==='true'}};
(async()=>{
  let pool;
  try{
    pool=await sql.connect(config);
    const hash=await bcrypt.hash(password,12);
    const r=await pool.request().input('u',sql.NVarChar(120),username.trim()).input('n',sql.NVarChar(180),displayName.trim()).input('e',sql.NVarChar(255),email).input('h',sql.NVarChar(255),hash)
      .query(`IF EXISTS(SELECT 1 FROM dbo.portal_users WHERE username=@u)
              BEGIN UPDATE dbo.portal_users SET display_name=@n,email=@e,password_hash=@h,role='ADMIN',is_active=1,updated_at=SYSUTCDATETIME() WHERE username=@u; SELECT id FROM dbo.portal_users WHERE username=@u; END
              ELSE BEGIN INSERT dbo.portal_users(username,display_name,email,password_hash,role,is_active) OUTPUT INSERTED.id VALUES(@u,@n,@e,@h,'ADMIN',1); END`);
    console.log(`Administrador configurado. ID: ${r.recordset[0].id}`);
  }catch(err){console.error('Falha ao criar administrador:',err.message);process.exitCode=1;}finally{if(pool)await pool.close();}
})();
