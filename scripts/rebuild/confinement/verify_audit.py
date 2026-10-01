"""Independent verifier for the probe's AuditEvent v1 chain and checkpoints.

Uses Python/cryptography, not Lumen's Rust verifier. The caller supplies a
separate trusted head and public key; a self-consistent truncated log fails.
These development anchors do not establish production host enrollment.
"""
import hashlib
import json
from pathlib import Path
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from runtime import Refused, unique_object


def canonical(value):
    def check(item):
        if isinstance(item, float):
            raise Refused("floating point is not canonical")
        if isinstance(item, dict):
            for child in item.values():
                check(child)
        if isinstance(item, list):
            for child in item:
                check(child)
    check(value)
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def verify(report, anchor):
    events, checkpoints = report["events"], report["checkpoints"]
    if not events or len(events) != anchor["through_seq"] + 1 or len(checkpoints) != len(events):
        raise Refused("audit gap or missing checkpoint")
    previous = "0" * 64
    required = {"version", "event_id", "sequence", "timestamp_ms", "actor", "kind", "session_id",
                "action_digest", "detail", "prev_hash", "hash"}
    kinds = {"action_proposed", "policy_allowed", "policy_denied", "approval_requested",
             "transport_rejected", "tool_executed"}
    for index, event in enumerate(events):
        if (set(event) - {"decision"} != required or type(event["version"]) is not int
                or event["version"] != 1 or event["sequence"] != index or event["prev_hash"] != previous
                or event["kind"] not in kinds):
            raise Refused("unknown audit contract or broken chain")
        calculated = hashlib.sha256(canonical({**event, "hash": ""}) + previous.encode()).hexdigest()
        if calculated != event["hash"]:
            raise Refused("audit hash mismatch")
        previous = calculated
    if previous != anchor["chain_hash"]:
        raise Refused("audit does not reach the trusted head")
    key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(anchor["verifying_key_hex"]))
    for index, checkpoint in enumerate(checkpoints):
        if (set(checkpoint) != {"key_id", "through_seq", "chain_hash", "signature"}
                or checkpoint["key_id"] != anchor["key_id"] or checkpoint["through_seq"] != index
                or checkpoint["chain_hash"] != events[index]["hash"]):
            raise Refused("checkpoint not anchored to the expected key and event")
        key.verify(bytes.fromhex(checkpoint["signature"]), canonical({
            name: checkpoint[name] for name in ("key_id", "through_seq", "chain_hash")}))
    decisions = [event for event in events if event["kind"] == "policy_denied"]
    if (len(decisions) != 1 or decisions[0].get("decision") != "deny"
            or decisions[0]["action_digest"] != report["reply"]["action_digest"]
            or report["reply"]["outcome"]["status"] != "denied"):
        raise Refused("reply does not identify the audited denial")


def load(path):
    raw = Path(path).read_bytes()
    if len(raw) > 256 * 1024:
        raise Refused("oversize audit evidence")
    return json.loads(raw, object_pairs_hook=unique_object)


if __name__ == "__main__":
    verify(load(sys.argv[1]), load(sys.argv[2]))
    print("Audit chain, exact denial digest, signed checkpoints and trusted head verified.")
