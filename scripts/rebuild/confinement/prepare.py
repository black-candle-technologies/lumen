"""Build a candidate test runtime. No candidate is automatically admitted.

The caller reviews/pins the emitted manifest digest separately from its contents.
Builds run on Linux; Node and its declared distro runtime libraries are copied,
never a general host filesystem mount. Pi packaging is a separate input step.
"""
from pathlib import Path
import json
import re
import shutil
import subprocess

from runtime import TOOLS, inventory, sha256


def copy_file(source: Path, root: Path, guest_path: str):
    target = root / guest_path.lstrip("/")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    target.chmod(0o755 if guest_path == "/usr/bin/node" or target.name.startswith("ld-linux-") else 0o644)


def system_runtime(root: Path):
    copy_file(Path("/usr/bin/node"), root, "/usr/bin/node")
    # ldd is restricted to the host's trusted system Node, never repository code.
    result = subprocess.run(["/usr/bin/ldd", "/usr/bin/node"], capture_output=True,
                            text=True, check=True, timeout=10)
    for library in re.findall(r"(?:=>\s+|^\s*)(/[^\s]+)", result.stdout, re.MULTILINE):
        copy_file(Path(library), root, library)
    variables = json.loads(subprocess.check_output([
        "/usr/bin/node", "-p", "JSON.stringify(process.config.variables)"], timeout=10))
    # Debian externalizes certain bundled builtins. Only declared absolute JS
    # inputs are copied. Their digests become explicit manifest entries.
    for key, value in variables.items():
        if key.startswith("node_shared_builtin_") and isinstance(value, str) and value.startswith("/"):
            copy_file(Path(value), root, value)
    # Ubuntu's system Node does not expose these configure-time paths through
    # process.config. Keep this compatibility inventory explicit and pinned;
    # never bind the entire /usr/share/nodejs dependency tree.
    for value in ("/usr/share/nodejs/cjs-module-lexer/lexer.js",
                  "/usr/share/nodejs/cjs-module-lexer/dist/lexer.js",
                  "/usr/share/nodejs/undici/undici-fetch.js",
                  "/usr/share/nodejs/acorn/dist/acorn.js",
                  "/usr/share/nodejs/acorn-walk/dist/walk.js",
                  "/usr/share/nodejs/minimatch/dist/cjs/index.bundle.js"):
        if Path(value).is_file():
            copy_file(Path(value), root, value)


def compile_guard(root: Path):
    here = Path(__file__).parent
    out = root / "guard/guard.node"
    out.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["/usr/bin/gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                    "-fPIC", "-shared", "-fstack-protector-strong", "-Wl,-z,relro,-z,now",
                    "-I/usr/include/node", "-o", str(out), str(here / "guard.c")],
                   check=True, timeout=30)
    copy_file(here / "bootstrap.cjs", root, "/guard/bootstrap.cjs")
    subprocess.run(["/usr/bin/gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                    "-fstack-protector-strong", "-Wl,-z,relro,-z,now", "-o",
                    str(root / "guard/liveness"), str(here / "liveness.c")], check=True, timeout=30)


def manifest_for(root: Path, output: Path, entrypoint: str, arguments=()):
    import os
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        files = sorted(inventory(fd))
    finally:
        os.close(fd)
    data = {"version": 2, "profile": "bwrap-stdio-liveness-v2", "platform": "linux-x86_64",
            "files": {path: sha256(root / path.lstrip("/")) for path in files},
            "host_tools": {name: sha256(Path(path)) for name, path in TOOLS.items()},
            "entrypoint": entrypoint, "arguments": list(arguments)}
    output.write_text(json.dumps(data, sort_keys=True, indent=2) + "\n")
    return sha256(output)
