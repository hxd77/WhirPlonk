#!/usr/bin/env bash
set -euo pipefail

ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
cd "$ROOT"

find . \
  -path './.git' -prune -o \
  -type d \( \
    -name build -o \
    -name 'build_*' -o \
    -name 'cmake-build-*' -o \
    -name CMakeFiles -o \
    -name .vs -o \
    -name .cache -o \
    -name __pycache__ -o \
    -name target \
  \) -prune -exec rm -rf {} +

find . \
  -path './.git' -prune -o \
  -type f \( \
    -name CMakeCache.txt -o \
    -name compile_commands.json -o \
    -name '*.obj' -o \
    -name '*.o' -o \
    -name '*.pdb' -o \
    -name '*.ilk' -o \
    -name '*.exp' -o \
    -name '*.lib' -o \
    -name '*.dll' -o \
    -name '*.exe' -o \
    -name '*.ninja' -o \
    -name .ninja_deps -o \
    -name .ninja_log -o \
    -name '*.pyc' \
  \) -delete

printf 'Generated build artifacts cleaned under %s\n' "$ROOT"
