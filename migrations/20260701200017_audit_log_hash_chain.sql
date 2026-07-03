-- Harden the audit-log hash chain with an advisory lock, a TRUNCATE guard,
-- and a deterministic genesis hash for the chain origin.

CREATE OR REPLACE FUNCTION audit_log_advisory_lock()
RETURNS void AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(42);
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION audit_log_reject_truncate()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'truncating audit_log is not allowed';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_log_reject_truncate
    BEFORE TRUNCATE ON audit_log
    EXECUTE FUNCTION audit_log_reject_truncate();

-- Backfill the oldest existing row so the chain has a deterministic origin.
-- The append-only trigger must be briefly disabled because this update is
-- the one trusted maintenance operation that mutates an existing row.
ALTER TABLE audit_log DISABLE TRIGGER audit_log_prevent_update_delete;
UPDATE audit_log
SET prev_hash = encode(sha256('audit-log-genesis'::bytea), 'hex')
WHERE id = (
    SELECT id FROM audit_log ORDER BY created_at ASC LIMIT 1
);
ALTER TABLE audit_log ENABLE TRIGGER audit_log_prevent_update_delete;
