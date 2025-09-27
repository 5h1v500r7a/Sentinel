#!/usr/bin/env python3
"""
sentinel: the command-line front door for the whole project.

Subcommands:
  sentinel run     --policy <file> -- <program> [args...]
  sentinel demo
  sentinel report  <violations.jsonl> [-o output.md]
  sentinel policies

Run `sentinel <subcommand> --help` for details on any of these.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import demo as demo_mod
from . import paths
from . import report as report_mod
from . import runner


def cmd_run(args: argparse.Namespace) -> int:
    policy_path = Path(args.policy)
    if not policy_path.is_absolute() and not policy_path.exists():
        # convenience: allow `--policy web-server.toml` to mean the
        # bundled policies/ directory, not just the CWD.
        candidate = paths.policies_dir() / policy_path.name
        if candidate.exists():
            policy_path = candidate
    if not policy_path.exists():
        print(f"error: policy file not found: {args.policy}", file=sys.stderr)
        return 2

    log_path = Path(args.log) if args.log else paths.logs_dir() / "violations.jsonl"
    return runner.run(policy_path, log_path, args.target)


def cmd_demo(_args: argparse.Namespace) -> int:
    demo_mod.run_demo()
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    log_path = Path(args.log_file)
    output = Path(args.output) if args.output else None
    text = report_mod.generate(log_path, output)
    if output is None:
        print(text)
    return 0


def cmd_policies(_args: argparse.Namespace) -> int:
    pdir = paths.policies_dir()
    print(f"Bundled policies in {pdir}:\n")
    for f in sorted(pdir.glob("*.toml")):
        print(f"  {f.name}")
        # print the first comment block as a quick description
        for line in f.read_text().splitlines()[2:6]:
            if line.startswith("#"):
                print(f"    {line.lstrip('# ')}")
        print()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="Sentinel Sandbox: a policy-driven Linux syscall firewall.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_run = sub.add_parser("run", help="Run a program under a sandbox policy")
    p_run.add_argument("--policy", required=True, help="Path to a .toml policy file")
    p_run.add_argument("--log", help="Where to write violations.jsonl (default: logs/violations.jsonl)")
    p_run.add_argument("target", nargs=argparse.REMAINDER,
                        help="The program (and its args) to sandbox, after --")
    p_run.set_defaults(func=cmd_run)

    p_demo = sub.add_parser("demo", help="Run the bundled attack-suite demo")
    p_demo.set_defaults(func=cmd_demo)

    p_report = sub.add_parser("report", help="Summarise a violations.jsonl log")
    p_report.add_argument("log_file", help="Path to a violations.jsonl file")
    p_report.add_argument("-o", "--output", help="Write the Markdown report to this file instead of stdout")
    p_report.set_defaults(func=cmd_report)

    p_policies = sub.add_parser("policies", help="List bundled policy templates")
    p_policies.set_defaults(func=cmd_policies)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # argparse.REMAINDER on `run` includes a leading "--" if the user
    # typed one; strip it so `target` is just the command+args.
    if args.command == "run" and args.target and args.target[0] == "--":
        args.target = args.target[1:]
    if args.command == "run" and not args.target:
        print("error: missing target command. Example:\n"
              "  sentinel run --policy web-server.toml -- ./my-server --port 8080",
              file=sys.stderr)
        return 2

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
