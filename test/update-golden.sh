#!/usr/bin/env bash
# Rebuild the committed emulator test programs (test/golden/) with GNU as for ns32k.
#   NS32K_BINUTILS=<binutils built for ns32k-netbsd> test/update-golden.sh
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$HERE/golden"
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
for v in default 532; do
	python3 "$HERE/emu_tests.py" "$T/$v" $v
	cp "$T/$v/emu.bin" "$HERE/golden/emu_$v.bin"
	cp "$T/$v/tests.txt" "$HERE/golden/tests_$v.txt"
	cp "$T/$v/emu.lst" "$HERE/golden/emu_$v.lst"
done
