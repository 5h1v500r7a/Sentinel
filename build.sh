#!/usr/bin/env bash
# build.sh -- builds every component of Sentinel Sandbox in the right
# order (C library first, since Rust links against it; everything else
# has no ordering dependency).
#
# Usage: ./build.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "== [1/4] C: seccomp/ptrace engine =="
make -C "$HERE/c"

echo "== [2/4] Rust: launcher =="
( cd "$HERE/rust" && cargo build --release )

echo "== [3/4] C++: log analyzer =="
make -C "$HERE/cpp"

echo "== [4/4] Demo attack suite (C) =="
make -C "$HERE/tests/attack_syscalls"
gcc -Wall -Wextra -O2 -static -D_GNU_SOURCE "$HERE/tests/good_server.c" -o "$HERE/tests/good_server"

echo
echo "All components built."
echo "Try it now:"
echo "  cd $HERE/python && python3 -m sentinel_cli.cli demo"
echo "or, if you installed the CLI (pip install -e python/):"
echo "  sentinel demo"
