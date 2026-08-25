/* Portal Pre-Vendas NDD - Fundacao MSSQL
   Execute este script no banco MSSQL da aplicacao.
   Nao contem credenciais de conexao.
*/

IF OBJECT_ID('dbo.portal_users', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.portal_users (
        id BIGINT IDENTITY(1,1) PRIMARY KEY,
        username NVARCHAR(120) NOT NULL UNIQUE,
        display_name NVARCHAR(180) NOT NULL,
        email NVARCHAR(255) NULL,
        password_hash NVARCHAR(255) NOT NULL,
        role NVARCHAR(20) NOT NULL CONSTRAINT DF_portal_users_role DEFAULT ('USER'),
        is_active BIT NOT NULL CONSTRAINT DF_portal_users_active DEFAULT (1),
        created_at DATETIME2(0) NOT NULL CONSTRAINT DF_portal_users_created DEFAULT (SYSUTCDATETIME()),
        updated_at DATETIME2(0) NOT NULL CONSTRAINT DF_portal_users_updated DEFAULT (SYSUTCDATETIME()),
        last_login_at DATETIME2(0) NULL,
        CONSTRAINT CK_portal_users_role CHECK (role IN ('ADMIN','USER'))
    );
END;
GO

IF OBJECT_ID('dbo.portal_sessions', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.portal_sessions (
        id UNIQUEIDENTIFIER NOT NULL PRIMARY KEY,
        user_id BIGINT NOT NULL,
        token_hash CHAR(64) NOT NULL UNIQUE,
        created_at DATETIME2(0) NOT NULL CONSTRAINT DF_portal_sessions_created DEFAULT (SYSUTCDATETIME()),
        expires_at DATETIME2(0) NOT NULL,
        revoked_at DATETIME2(0) NULL,
        ip_address NVARCHAR(64) NULL,
        user_agent NVARCHAR(1000) NULL,
        CONSTRAINT FK_portal_sessions_user FOREIGN KEY (user_id) REFERENCES dbo.portal_users(id)
    );
    CREATE INDEX IX_portal_sessions_user ON dbo.portal_sessions(user_id, expires_at);
END;
GO

IF OBJECT_ID('dbo.portal_login_log', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.portal_login_log (
        id BIGINT IDENTITY(1,1) PRIMARY KEY,
        user_id BIGINT NULL,
        username_attempted NVARCHAR(120) NULL,
        success BIT NOT NULL,
        occurred_at DATETIME2(0) NOT NULL CONSTRAINT DF_portal_login_log_date DEFAULT (SYSUTCDATETIME()),
        ip_address NVARCHAR(64) NULL,
        user_agent NVARCHAR(1000) NULL,
        failure_reason NVARCHAR(255) NULL,
        CONSTRAINT FK_portal_login_log_user FOREIGN KEY (user_id) REFERENCES dbo.portal_users(id)
    );
    CREATE INDEX IX_portal_login_log_user_date ON dbo.portal_login_log(user_id, occurred_at DESC);
END;
GO

IF OBJECT_ID('dbo.portal_action_log', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.portal_action_log (
        id BIGINT IDENTITY(1,1) PRIMARY KEY,
        user_id BIGINT NOT NULL,
        action_type NVARCHAR(80) NOT NULL,
        product NVARCHAR(40) NULL,
        client_name NVARCHAR(255) NULL,
        client_document NVARCHAR(1000) NULL,
        payload_json NVARCHAR(MAX) NULL,
        result_json NVARCHAR(MAX) NULL,
        page_path NVARCHAR(500) NULL,
        occurred_at DATETIME2(0) NOT NULL CONSTRAINT DF_portal_action_log_date DEFAULT (SYSUTCDATETIME()),
        ip_address NVARCHAR(64) NULL,
        CONSTRAINT FK_portal_action_log_user FOREIGN KEY (user_id) REFERENCES dbo.portal_users(id),
        CONSTRAINT CK_portal_action_payload_json CHECK (payload_json IS NULL OR ISJSON(payload_json) = 1),
        CONSTRAINT CK_portal_action_result_json CHECK (result_json IS NULL OR ISJSON(result_json) = 1)
    );
    CREATE INDEX IX_portal_action_log_user_date ON dbo.portal_action_log(user_id, occurred_at DESC);
    CREATE INDEX IX_portal_action_log_product_date ON dbo.portal_action_log(product, occurred_at DESC);
END;
GO

IF OBJECT_ID('dbo.portal_generated_documents', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.portal_generated_documents (
        id BIGINT IDENTITY(1,1) PRIMARY KEY,
        user_id BIGINT NOT NULL,
        action_log_id BIGINT NULL,
        document_type NVARCHAR(40) NOT NULL,
        product NVARCHAR(40) NOT NULL,
        client_name NVARCHAR(255) NULL,
        snapshot_json NVARCHAR(MAX) NOT NULL,
        generated_at DATETIME2(0) NOT NULL CONSTRAINT DF_portal_documents_date DEFAULT (SYSUTCDATETIME()),
        CONSTRAINT FK_portal_documents_user FOREIGN KEY (user_id) REFERENCES dbo.portal_users(id),
        CONSTRAINT FK_portal_documents_action FOREIGN KEY (action_log_id) REFERENCES dbo.portal_action_log(id),
        CONSTRAINT CK_portal_documents_type CHECK (document_type IN ('EXTRATO','PROPOSTA')),
        CONSTRAINT CK_portal_documents_json CHECK (ISJSON(snapshot_json) = 1)
    );
    CREATE INDEX IX_portal_documents_user_date ON dbo.portal_generated_documents(user_id, generated_at DESC);
END;
GO
