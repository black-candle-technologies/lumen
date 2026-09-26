"""Mutation tests for the independent verifier, including truncation."""
import copy
import hashlib
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from verify_audit import canonical, verify


class AuditVerifierTests(unittest.TestCase):
    def setUp(self):
        key = Ed25519PrivateKey.generate()
        event = {"version": 1, "event_id": "b1a1c9c8-1256-497e-9f9a-e86489095c87",
                 "sequence": 0, "timestamp_ms": 1, "actor": {"actor": "kernel"},
                 "kind": "policy_denied", "session_id": "fixture", "action_digest": "a" * 64,
                 "decision": "deny", "detail": "{}", "prev_hash": "0" * 64, "hash": ""}
        event["hash"] = hashlib.sha256(canonical(event) + event["prev_hash"].encode()).hexdigest()
        checkpoint = {"key_id": "fixture-host", "through_seq": 0, "chain_hash": event["hash"]}
        self.anchor = {**checkpoint, "verifying_key_hex": key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()}
        checkpoint["signature"] = key.sign(canonical(checkpoint)).hex()
        self.report = {"events": [event], "checkpoints": [checkpoint],
                       "reply": {"action_digest": "a" * 64, "outcome": {"status": "denied"}}}

    def test_positive_chain(self):
        verify(self.report, self.anchor)

    def test_mutations_fail_closed(self):
        def change_event(r):
            r["events"][0]["detail"] = '{"changed":true}'
        def change_signature(r):
            r["checkpoints"][0]["signature"] = "00" * 64
        def change_digest(r):
            r["reply"]["action_digest"] = "b" * 64
        def change_key(r):
            r["checkpoints"][0]["key_id"] = "other-host"
        def truncate(r):
            r["events"] = []
            r["checkpoints"] = []
        def remove_checkpoint(r):
            r["checkpoints"] = []
        def unknown_version(r):
            r["events"][0]["version"] = 2
        for mutate in (change_event, change_signature, change_digest, change_key, truncate,
                       remove_checkpoint, unknown_version):
            with self.subTest(mutation=mutate.__name__):
                report = copy.deepcopy(self.report)
                mutate(report)
                with self.assertRaises(Exception):
                    verify(report, self.anchor)


if __name__ == "__main__":
    unittest.main(verbosity=2)
