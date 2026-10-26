#!/usr/bin/env bash
# Build dumpopc (dumps GNU binutils' NS32000 opcode table) from a binutils source tree.
#   test/build-dumpopc.sh <out-binary>
# BINUTILS_SRC: binutils source tree (for include/opcode/ns32k.h)
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
: "${BINUTILS_SRC:=$HOME/.cache/ghidra-rare-scratch/tools/bu/binutils-2.45}"
gcc -I"$BINUTILS_SRC/include" "$HERE/dumpopc.c" -o "$1"
