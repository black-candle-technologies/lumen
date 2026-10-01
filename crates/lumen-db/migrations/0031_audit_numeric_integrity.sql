-- AuditEvent stays v1: its signed representation is unchanged. Enforce the
-- existing exact-version contract for new rows without rewriting prior bytes.
INSERT INTO kernel_contract_versions(contract,version) VALUES ('audit_event',1);
CREATE TRIGGER kernel_audit_events_version_guard BEFORE INSERT ON kernel_audit_events
WHEN NEW.version <> 1
BEGIN SELECT RAISE(ABORT,'unsupported audit event version'); END;
