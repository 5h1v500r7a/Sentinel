"""
Runs the bundled "attack suite" (tests/attack_syscalls/) against the
policies it's each meant to illustrate, and prints a plain-English
explanation of what should happen and why -- this is the single command
a recruiter or a curious beginner should run first.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

from . import paths
from . import runner

SCENARIOS = [
    {
        "title": "1. Untrusted script tries to attach a debugger (ptrace)",
        "policy": "untrusted-script.toml",
        "binary": "evil_ptrace",
        "expect": "BLOCKED",
        "explanation": (
            "ptrace() is how a debugger attaches to a process -- and also "
            "how malware injects code into another running process or "
            "detects it's being sandboxed. A short-lived script has no "
            "legitimate reason to call it, so untrusted-script.toml denies "
            "it outright."
        ),
    },
    {
        "title": "2. Untrusted script tries to open a network socket",
        "policy": "untrusted-script.toml",
        "binary": "evil_socket",
        "expect": "BLOCKED",
        "explanation": (
            "socket() is the first step of exfiltrating data or phoning "
            "home to a command-and-control server. A CPU/file-bound batch "
            "job should never need the network at all, so it's denied."
        ),
    },
    {
        "title": "3. A trusted CLI tool spawns a shell (known limitation)",
        "policy": "cli-tool.toml",
        "binary": "evil_shell",
        "expect": "NOT BLOCKED",
        "explanation": (
            "cli-tool.toml allows execve() because legitimate CLI tools "
            "(build scripts, package managers) routinely shell out to "
            "other programs. A plain allow-list can't tell 'the target "
            "program's own launch' apart from 'the target re-executing "
            "something else' -- both are just an execve() syscall. This "
            "is a real, documented limitation of syscall-name allow-lists "
            "(see README.md's 'Known limitation' section), not a bug."
        ),
    },
]


def run_demo() -> None:
    for i, scenario in enumerate(SCENARIOS):
        print(f"\n{'=' * 70}")
        print(scenario["title"])
        print("=" * 70)
        print(scenario["explanation"])
        print(f"\nExpected result: {scenario['expect']}\n")

        policy_path = paths.policies_dir() / scenario["policy"]
        binary_path = paths.attack_suite_dir() / scenario["binary"]
        paths.check_build(
            f"demo binary {scenario['binary']}", binary_path,
            "cd tests/attack_syscalls && make",
        )
        log_path = paths.logs_dir() / f"demo-{i}-violations.jsonl"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text("")  # start each scenario with a clean log

        print(f"$ sentinel run --policy {scenario['policy']} -- {scenario['binary']}\n")
        runner.run(policy_path, log_path, [str(binary_path)])

        violations = log_path.read_text().strip()
        if violations:
            print(f"\n>>> Result: BLOCKED. Violation log:\n{violations}")
        else:
            print("\n>>> Result: NOT blocked (program ran to completion).")

    print(f"\n{'=' * 70}")
    print("Demo complete. Run `sentinel report logs/demo-0-violations.jsonl` "
          "(or any of the demo-N logs above) to see the C++ analyzer's "
          "severity-scored summary of a specific scenario.")
    print("=" * 70)
