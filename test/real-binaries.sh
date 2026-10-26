#!/usr/bin/env bash
# Real-code run: import NetBSD/pc532 a.out programs and libraries headless (the a.out loader picks the
# NS32532 variant), analyse them, and report instruction, function, bookmark and decompiler counts;
# every disassembled instruction is also compared with GNU libopcodes at the same address.
#   test/real-binaries.sh <workdir> <samples-dir> [decompile-limit]
# Needs GHIDRA_INSTALL_DIR (the module linked under Ghidra/Processors/NS32016 with lib/NS32016.jar built by
# test/build-jar.sh) and test/slotdis (test/build-slotdis.sh).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
W=$(readlink -m "${1:?workdir}")
S=$(readlink -m "${2:?samples dir}")
LIMIT=${3:-100}
: "${SLOTDIS:=$W/slotdis}"
: "${OBJDUMP:=$HOME/.cache/ghidra-rare-scratch/tools/binutils-all/bin/objdump}"
mkdir -p "$W/real"
[[ -x $SLOTDIS ]] || "$HERE/build-slotdis.sh" "$SLOTDIS"
if [[ ! -f $W/opc.txt ]]; then
	"$HERE/build-dumpopc.sh" "$W/dumpopc" && "$W/dumpopc" > "$W/opc.txt"
fi
PROGS=(
	base/bin/ls base/bin/sh base/bin/ksh base/bin/csh base/bin/ed base/bin/expr base/bin/pax
	base/usr/bin/tar base/usr/bin/gzip base/usr/bin/awk base/usr/bin/vi base/usr/bin/sort base/usr/bin/ftp
	base/usr/sbin/named base/sbin/dump
	base/usr/lib/libc.so.12.62.1 base/usr/lib/libm.so.0.1 base/usr/lib/libcrypto.so.0.2 base/usr/lib/libz.so.0.2
	base/usr/lib/libstdc++.so.2.0 base/usr/lib/libg2c.so.0.0
	comp/usr/libexec/cc1 comp/usr/libexec/cc1plus comp/usr/libexec/f771 comp/usr/bin/gdb comp/usr/bin/as
	comp/usr/bin/ld comp/usr/bin/ar comp/usr/bin/gprof comp/usr/bin/flex comp/usr/bin/objdump
)
rm -f "$W/real/summary.txt"
total_i=0
for p in "${PROGS[@]}"; do
	f="$S/$p"
	[[ -f $f ]] || { echo "missing $p" >&2; continue; }
	n=$(echo "$p" | tr '/' '_')
	"$HERE/ghidra-script.sh" auto - "$f" RealCheck.java "$W/real/$n.sum" "$W/real/$n.lst" "$LIMIT"
	awk '{print $1}' "$W/real/$n.lst" > "$W/real/$n.addrs"
	"$SLOTDIS" "$f" list 1000 "$W/real/$n.addrs" > "$W/real/$n.ref"
	cmp=$(python3 "$HERE/real_compare.py" "$W/real/$n.lst" "$W/real/$n.ref" --list 1 --opc "$W/opc.txt" --show 5 --variant 532 || true)
	insns=$(sed -n 's/^instructions //p' "$W/real/$n.sum")
	funcs=$(sed -n 's/^functions //p' "$W/real/$n.sum")
	bad=$(sed -n 's/^bookmark Error\/Bad Instruction //p' "$W/real/$n.sum")
	dec=$(sed -n 's/^decompiled //p' "$W/real/$n.sum")
	match=$(echo "$cmp" | sed -n 's/^ *\([0-9]*\) match$/\1/p')
	echo "$p: instructions $insns functions $funcs bad-instruction ${bad:-0} decompiled $dec; vs libopcodes: ${match:-0} identical" | tee -a "$W/real/summary.txt"
	echo "$cmp" | grep -v "^ *[0-9]* match$" | sed 's/^/    /' >> "$W/real/summary.txt" || true
done
