-- Append-only audit log with an integrity hash chain.

ALTER TABLE audit_log
    ADD COLUMN prev_hash TEXT NOT NULL DEFAULT '',
    ADD COLUMN integrity_hash TEXT NOT NULL DEFAULT '';

-- Backfill existing rows with a stable hash over their primary fields so the
-- chain is not broken for new inserts.
UPDATE audit_log
SET integrity_hash = encode(
    sha256(
        (id || '|' || COALESCE(tenant_id, '') || '|' || COALESCE(actor, '') || '|' ||
        action || '|' || resource || '|' || outcome || '|' || metadata::text || '|' ||
        prev_hash || '|' || created_at::text)::bytea
    ),
    'hex'
)
WHERE integrity_hash = '';

CREATE OR REPLACE FUNCTION audit_log_append_only()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_log_prevent_update_delete
    BEFORE UPDATE OR DELETE ON audit_log
    EXECUTE FUNCTION audit_log_append_only();
