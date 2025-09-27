"""
Thin subprocess wrapper around the Rust `sentinel-launcher` binary.
"""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Sequence

from . import paths


def run(policy_path: Path, log_path: Path, target_cmd: Sequence[str]) -> int:
    """Runs `target_cmd` under `policy_path`, streaming its stdout/stderr
    straight through to ours (so you see the sandboxed program's own
    output live). Returns the launcher's own process exit code (which
    mirrors the sandboxed program's fate -- see rust/src/main.rs)."""
    launcher = paths.rust_launcher_bin()
    paths.check_build(
        "sentinel-launcher (Rust)", launcher,
        "cd rust && cargo build --release",
    )
    lib = paths.c_lib_dir() / "libsentinel_filter.so"
    paths.check_build(
        "libsentinel_filter.so (C)", lib,
        "cd c && make",
    )

    log_path.parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        str(launcher),
        "--policy", str(policy_path),
        "--log", str(log_path),
        "--",
        *target_cmd,
    ]
    result = subprocess.run(cmd, env=paths.env_with_ld_library_path())
    return result.returncode
