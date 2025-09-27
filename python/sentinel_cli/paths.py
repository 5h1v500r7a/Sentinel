"""
Central place that knows where everything in this repo lives, so the
rest of the CLI never has to guess a relative path. If you move files
around, this is the one file to update.
"""
from __future__ import annotations

import os
from pathlib import Path


def project_root() -> Path:
    """The sentinel-sandbox/ directory, found relative to this file
    rather than the current working directory, so `sentinel` works
    correctly no matter where you invoke it from."""
    # this file is at <root>/python/sentinel_cli/paths.py
    return Path(__file__).resolve().parents[2]


def c_lib_dir() -> Path:
    return project_root() / "c" / "build"


def rust_launcher_bin() -> Path:
    return project_root() / "rust" / "target" / "release" / "sentinel-launcher"


def cpp_analyzer_bin() -> Path:
    return project_root() / "cpp" / "build" / "sentinel-log-analyzer"


def policies_dir() -> Path:
    return project_root() / "policies"


def logs_dir() -> Path:
    return project_root() / "logs"


def attack_suite_dir() -> Path:
    return project_root() / "tests" / "attack_syscalls" / "build"


def good_server_bin() -> Path:
    return project_root() / "tests" / "good_server"


def env_with_ld_library_path() -> dict:
    """Returns a copy of the current environment with c/build/ prepended
    to LD_LIBRARY_PATH, so the dynamically-linked sentinel-launcher can
    find libsentinel_filter.so without the user needing to export
    anything themselves."""
    env = os.environ.copy()
    existing = env.get("LD_LIBRARY_PATH", "")
    lib_dir = str(c_lib_dir())
    env["LD_LIBRARY_PATH"] = f"{lib_dir}:{existing}" if existing else lib_dir
    return env


def check_build(component: str, path: Path, build_hint: str) -> None:
    """Raises a clear, actionable error if a required binary is missing,
    instead of letting subprocess fail with a cryptic FileNotFoundError."""
    if not path.exists():
        raise SystemExit(
            f"error: {component} not found at {path}\n"
            f"  Build it first: {build_hint}"
        )
