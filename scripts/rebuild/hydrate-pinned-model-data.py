#!/usr/bin/env python3
"""Recover offline build data from one byte-pinned upstream release artifact.

The source generator fetches mutable provider catalogues. Never run it as a
network-enabled build fallback. This input is a review candidate, not admission.
"""
import hashlib
import io
from pathlib import Path
import sys
import tarfile
import urllib.request

URL = "https://registry.npmjs.org/@earendil-works/pi-ai/-/pi-ai-0.87.1.tgz"
SHA256 = "35b4432f27cc2665f86beebb9af6a39b1251970883c3044bd8be4f4e8c731ca0"
PREFIX = "package/dist/providers/data/"


def hydrate(repository: Path):
    with urllib.request.urlopen(URL, timeout=30) as response:
        raw = response.read(8 * 1024 * 1024 + 1)
    if len(raw) > 8 * 1024 * 1024 or hashlib.sha256(raw).hexdigest() != SHA256:
        raise ValueError("model-data release artifact digest mismatch")
    files = {}
    total = 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
        for member in archive:
            if not member.name.startswith(PREFIX):
                continue
            name = member.name[len(PREFIX):]
            if (not member.isfile() or "/" in name or not name.endswith(".json")
                    or name in files or member.size > 1024 * 1024 or len(files) >= 64):
                raise ValueError("invalid model-data archive entry")
            data = archive.extractfile(member).read(1024 * 1024 + 1)
            total += len(data)
            if len(data) != member.size or total > 8 * 1024 * 1024:
                raise ValueError("model-data archive exceeds limits")
            files[name] = data
    if ".manifest.json" not in files:
        raise ValueError("model-data manifest missing")
    target = repository / "packages/ai/src/providers/data"
    if target.exists():
        if target.is_symlink() or set(p.name for p in target.iterdir()) != set(files):
            raise ValueError("existing model-data inventory mismatch")
        for name, data in files.items():
            path = target / name
            if path.is_symlink() or not path.is_file() or path.read_bytes() != data:
                raise ValueError("existing model-data bytes differ from pinned release")
    else:
        target.mkdir(parents=True, exist_ok=False)
        for name, data in files.items():
            (target / name).write_bytes(data)
    print(f"Pinned offline model data: {len(files)} files, artifact sha256:{SHA256}")


if __name__ == "__main__":
    hydrate(Path(sys.argv[1]))
