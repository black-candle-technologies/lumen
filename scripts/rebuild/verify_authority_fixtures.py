#!/usr/bin/env python3
"""Independently verify Phase 1 scope and lease fixtures; no signing keys.

Run with Python 3 and cryptography. This verifier does not import or invoke
Lumen. Fixtures use a publicly known test-vector key, never production keys.
"""
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


FIXTURES = Path(__file__).resolve().parents[2] / "crates/lumen-core/tests/fixtures"


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate fixture key")
        result[key] = value
    return result


def read(name):
    return json.loads((FIXTURES / name).read_text(), object_pairs_hook=unique_object)


def canonical(value):
    if isinstance(value, float):
        raise ValueError("non-integer fixture number")
    if isinstance(value, dict):
        for item in value.values():
            canonical(item)
    elif isinstance(value, list):
        for item in value:
            canonical(item)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def main():
    fixture = read("resource_scope.v2.json")
    scope = fixture["scope"]
    require(set(scope) == {"tools", "paths", "destinations", "secrets", "accounts", "models", "effects"},
            "unexpected resource dimension")
    # Typed dimensions; only set-valued vectors are sorted and deduplicated.
    encoded = {"contract": "lumen.resource-scope", "version": 2, **scope}
    for dimension in ("paths", "destinations", "effects"):
        members = {canonical(item): item for item in scope[dimension]}
        encoded[dimension] = [members[key] for key in sorted(members)]
    require(encoded == fixture["canonical"], "scope canonical value mismatch")
    require(hashlib.sha256(canonical(encoded)).hexdigest() == fixture["digest"], "scope digest mismatch")

    for version, name in ((2, "lease.legacy-v2.json"), (3, "lease.v3.json")):
        fixture = read(name)
        document = dict(fixture["document"])
        signature = bytes.fromhex(document.pop("signature"))
        require(document["protocol_version"] == version, "lease version mismatch")
        require(document["scope"] == scope, "lease fixture scope mismatch")
        encoded = canonical(document)
        require(hashlib.sha256(encoded).hexdigest() == fixture["signing_digest"], "lease digest mismatch")
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(fixture["test_public_key"])).verify(signature, encoded)
        if version == 2:
            require(document["limits"]["budget"]["tokens"] == 0, "historical explicit zero missing")
    print("Verified scope v2 digest and legacy-v2/v3 lease signatures independently")


if __name__ == "__main__":
    main()
