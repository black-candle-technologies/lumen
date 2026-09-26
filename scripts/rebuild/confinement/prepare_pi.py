"""Package a built, unmodified upstream Pi into an exact candidate inventory.

No npm installation, discovery, or symlink is included in the runtime. This
test candidate is not signed/admitted and cannot enable product supervisors.
"""
from pathlib import Path
import shutil
import subprocess
import sys

from prepare import compile_guard, copy_file, manifest_for, system_runtime


def tree(source: Path, target: Path):
    for item in sorted(source.rglob("*")):
        if item.is_symlink():
            raise ValueError("runtime source contains a symlink")
        if item.is_file():
            destination = target / item.relative_to(source)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(item, destination)
        elif not item.is_dir():
            raise ValueError("runtime source contains a special file")


def prepare_pi(repository: Path, destination: Path):
    destination.mkdir(exist_ok=False)
    root = destination / "root"
    root.mkdir()
    system_runtime(root)
    compile_guard(root)
    subprocess.run(["/usr/bin/gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                    "-fPIC", "-shared", "-I/usr/include/node", "-o", str(root / "guard/probe.node"),
                    str(Path(__file__).with_name("probe.c"))], check=True, timeout=30)
    # Full dist trees preserve upstream relative paths and extension aliases.
    # The executable is always the upstream CLI; no embedding or SDK entrypoint.
    for directory, package in (("coding-agent", "pi-coding-agent"), ("ai", "pi-ai"),
                               ("agent", "pi-agent-core"), ("tui", "pi-tui"),
                               ("telemetry", "pi-telemetry"), ("chord", "chord")):
        guest = "/node_modules/@earendil-works/" + package
        source = repository / "packages" / directory
        copy_file(source / "package.json", root, guest + "/package.json")
        tree(source / "dist", root / guest.lstrip("/") / "dist")
    for package in ("jiti", "typebox", "@silvia-odwyer/photon-node", "esbuild"):
        tree(repository / "node_modules" / package, root / "node_modules" / package)
    (root / "fixtures").mkdir()
    copy_file(Path(__file__).with_name("pi-probe.mjs"), root, "/fixtures/pi-probe.mjs")
    # JS emitted from the actual BCT bridge source by its existing test build.
    project = Path(__file__).resolve().parents[3]
    copy_file(project / "lumen-integrations/bct-pi-extension/.test-build/host-client.js",
              root, "/fixtures/host-client.mjs")
    args = ["--mode", "rpc", "--no-builtin-tools", "--tools", "bct.read_file", "--no-extensions", "--no-skills",
            "--no-prompt-templates", "--no-themes", "--no-session",
            "-e", "/fixtures/pi-probe.mjs", "--provider", "lumen-fixture",
            "--model", "one", "--thinking", "off"]
    entrypoint = "/node_modules/@earendil-works/pi-coding-agent/dist/bundle/cli.js"
    print(manifest_for(root, destination / "manifest.json", entrypoint, args))


if __name__ == "__main__":
    prepare_pi(Path(sys.argv[1]), Path(sys.argv[2]))
