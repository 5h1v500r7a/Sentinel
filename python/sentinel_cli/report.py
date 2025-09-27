"""
Wraps the compiled C++ log analyzer (cpp/build/sentinel-log-analyzer).

Kept intentionally simple: the analyzer already does the real work and
prints Markdown; this module just calls it and, optionally, saves the
result to a file the user can open or attach to a portfolio/write-up.
"""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Optional

from . import paths


def generate(log_path: Path, output_md: Optional[Path] = None) -> str:
    analyzer = paths.cpp_analyzer_bin()
    paths.check_build(
        "sentinel-log-analyzer (C++)", analyzer,
        "cd cpp && make",
    )

    if not log_path.exists():
        return (
            f"# Sentinel Violation Report\n\n"
            f"No log file found at `{log_path}`. Run `sentinel run` or "
            f"`sentinel demo` first to generate one.\n"
        )

    args = [str(analyzer), str(log_path)]
    if output_md is not None:
        output_md.parent.mkdir(parents=True, exist_ok=True)
        args.append(str(output_md))
        subprocess.run(args, check=True)
        return output_md.read_text()
    else:
        result = subprocess.run(args, check=True, capture_output=True, text=True)
        return result.stdout
