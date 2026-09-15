CREATE TABLE uem_oidc_accounts (
    user_id TEXT PRIMARY KEY REFERENCES users(uid) ON DELETE RESTRICT,
    revision BIGINT NOT NULL DEFAULT 0 CHECK (revision >= 0)
);
CREATE TABLE uem_oidc_bindings (
    issuer TEXT NOT NULL CHECK (octet_length(issuer) BETWEEN 1 AND 2048),
    subject TEXT NOT NULL CHECK (octet_length(subject) BETWEEN 1 AND 255),
    user_id TEXT NOT NULL REFERENCES uem_oidc_accounts(user_id) ON DELETE RESTRICT,
    active BOOLEAN NOT NULL,
    PRIMARY KEY (issuer, subject)
);
CREATE UNIQUE INDEX uem_oidc_active_account_issuer ON uem_oidc_bindings(user_id, issuer) WHERE active;
CREATE INDEX uem_oidc_account_bindings ON uem_oidc_bindings(user_id, issuer, subject);
CREATE TABLE uem_oidc_audit (
    id BIGSERIAL PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES uem_oidc_accounts(user_id) ON DELETE RESTRICT,
    revision BIGINT NOT NULL CHECK (revision > 0),
    actor TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('create', 'link', 'enable', 'disable')),
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(user_id, revision)
);
