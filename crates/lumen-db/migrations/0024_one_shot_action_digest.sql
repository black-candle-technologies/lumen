-- 0024: bind one-shot leases to the approved action digest.
--
-- Phase 1 added `LeaseDocument.approved_action_digest` (`LEASE_PROTOCOL_VERSION`
-- 1 -> 2): `mint_one_shot_lease` records `Some(action.digest)` and the issuer
-- signature covers it via `LeaseSigningView`, so `authorize_envelope` can
-- re-check that the presented action is the exact action a human approved.
-- Standing leases store NULL. Legacy one-shot rows (NULL digest) fail closed
-- at authorization: the kernel denies any single-use lease whose recorded
-- digest does not match the presented action, and NULL never matches.
ALTER TABLE kernel_leases ADD COLUMN approved_action_digest TEXT NULL;
