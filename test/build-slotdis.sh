#!/usr/bin/env bash
# Build slotdis (one-instruction-per-slot GNU libopcodes ns32k disassembler) against an installed binutils.
#   test/build-slotdis.sh <out-binary>
# BINUTILS_INC: directory with bfd.h and dis-asm.h; BINUTILS_LIB: directory with libopcodes.a, libbfd.a,
# libsframe.a; LIBIBERTY: a host libiberty.a
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
: "${BINUTILS_INC:=$HOME/.cache/ghidra-rare-scratch/tools/binutils-all/include}"
: "${BINUTILS_LIB:=$HOME/.cache/ghidra-rare-scratch/tools/binutils-all/lib}"
: "${LIBIBERTY:=$HOME/.cache/ghidra-rare-scratch/tools/bu/build/libiberty/libiberty.a}"
gcc -I"$BINUTILS_INC" "$HERE/slotdis.c" "$BINUTILS_LIB/libopcodes.a" "$BINUTILS_LIB/libbfd.a" \
	"$LIBIBERTY" "$BINUTILS_LIB/libsframe.a" -lz -lzstd -o "$1"
