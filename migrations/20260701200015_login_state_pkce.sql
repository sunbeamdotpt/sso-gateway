-- Add PKCE and OIDC nonce storage to login_state.
ALTER TABLE login_state
    ADD COLUMN IF NOT EXISTS code_verifier TEXT,
    ADD COLUMN IF NOT EXISTS nonce TEXT;
