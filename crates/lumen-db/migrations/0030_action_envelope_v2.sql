-- Strict envelope and transport versions. Historical authority/audit bytes
-- remain immutable; no old approval is converted into new authority.
INSERT INTO kernel_contract_versions(contract,version) VALUES
 ('action_envelope',2),('kernel_wire',2),('policy_decision',3),('host_action_channel',2);
