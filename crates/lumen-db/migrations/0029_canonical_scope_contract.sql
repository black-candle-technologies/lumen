-- Canonical scope v2 / LeaseDocument v3. Old records remain immutable evidence.
-- Do not rewrite a signed scope, its digest, approvals, or any audit payload.
CREATE TABLE kernel_contract_versions(
 contract TEXT NOT NULL,
 version INTEGER NOT NULL CHECK(version > 0),
 PRIMARY KEY(contract,version)
) STRICT;
INSERT INTO kernel_contract_versions(contract,version) VALUES
 ('lease_document',3),('resource_scope_digest',2);
CREATE TRIGGER kernel_contract_versions_no_update BEFORE UPDATE ON kernel_contract_versions
BEGIN SELECT RAISE(ABORT,'kernel contract versions are immutable'); END;
CREATE TRIGGER kernel_contract_versions_no_delete BEFORE DELETE ON kernel_contract_versions
BEGIN SELECT RAISE(ABORT,'kernel contract versions are immutable'); END;
CREATE TRIGGER kernel_leases_current_contract BEFORE INSERT ON kernel_leases
WHEN NEW.protocol_version != 3
BEGIN SELECT RAISE(ABORT,'unsupported lease contract version'); END;
