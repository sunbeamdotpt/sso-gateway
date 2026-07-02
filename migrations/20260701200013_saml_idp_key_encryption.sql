-- Encrypt SAML IdP signing keys at rest.

ALTER TABLE saml_idp_keys
    ADD COLUMN encrypted_private_key TEXT;

-- Backfill existing rows by leaving the plaintext in the legacy column until
-- the application re-encrypts them on first access with the configured key.
-- Rows with a non-null legacy private_key_pem and a null encrypted_private_key
-- will be rejected at runtime unless the encryption key is configured.
