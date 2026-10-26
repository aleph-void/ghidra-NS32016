#!/usr/bin/env bash
# NS32016 module test suite: everything that needs no downloaded inputs.
#
#   GHIDRA_INSTALL_DIR=<scratch Ghidra 12.1.x> test/run-tests.sh [workdir] [--real]
#
# 1. the generator reproduces the checked-in SLEIGH (both variants)
# 2. both specs compile (.sla well under 16 MB)
# 3. decode differential against GNU libopcodes (and MAME unidasm when installed): every entry of the
#    binutils opcode table x all 32 x 32 addressing-mode field values, plus random words; every
#    difference is classified by test/compare.py and the run fails on any unexplained one
# 4. every SLEIGH constructor is reached by that corpus
# 5. p-code: hand-computed and model-generated emulator tests, including deliberately wrong
#    expectations that must be reported
# --real adds step 6: NetBSD/pc532 binaries fetched by test/fetch-real-samples.sh (pinned URL and
#    SHA-256), imported with the a.out loader, analysed, decompiled and compared with libopcodes.
#
# Environment:
#   GHIDRA_INSTALL_DIR  a scratch copy of Ghidra 12.1.x; the module is symlinked into its
#                       Ghidra/Processors/NS32016 (an existing different entry is left alone) and
#                       lib/NS32016.jar is rebuilt
#   JAVA_HOME           a JDK with javac (Ghidra 12.1 runs on 21 or 25)
#   BINUTILS_SRC / BINUTILS_INC / BINUTILS_LIB / LIBIBERTY
#                       a binutils 2.45 source tree (include/opcode/ns32k.h) and an installed build with
#                       libopcodes.a/libbfd.a that has the ns32k target (see test/build-slotdis.sh)
#   NS32K_BINUTILS      binutils built for ns32k-netbsd (gas, ld, objcopy, nm) to rebuild the emulator
#                       test programs; without it the committed test/golden/ programs are used
#   UNIDASM             MAME's unidasm (default: unidasm on PATH; skipped when missing)
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
MOD=$(cd "$HERE/.." && pwd)
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR to a scratch Ghidra 12.1.x}"
REAL=0
ARGS=()
for a in "$@"; do if [[ $a == --real ]]; then REAL=1; else ARGS+=("$a"); fi; done
W=$(readlink -m "${ARGS[0]:-${TMPDIR:-/tmp}/ns32016-tests}")
mkdir -p "$W"
UNIDASM=${UNIDASM:-$(command -v unidasm || true)}
if [[ -z ${JAVA_HOME:-} && -x /usr/lib/jvm/java-25-openjdk-amd64/bin/javac ]]; then
	export JAVA_HOME=/usr/lib/jvm/java-25-openjdk-amd64
fi
export GHIDRA_INSTALL_DIR
fail=0

echo "== 1. generator reproduces the checked-in specs"
python3 "$MOD/tools/gen_ns32016.py" default | cmp - "$MOD/data/languages/NS32016.slaspec"
python3 "$MOD/tools/gen_ns32016.py" 532 | cmp - "$MOD/data/languages/NS32532.slaspec"

echo "== 2. SLEIGH compiles"
for s in NS32016 NS32532; do
	"$GHIDRA_INSTALL_DIR/support/sleigh" "$MOD/data/languages/$s.slaspec" 2>&1 | grep -E "^ERROR" && exit 1 || true
	sz=$(stat -c %s "$MOD/data/languages/$s.sla")
	echo "   $s.sla: $sz bytes"
	((sz < 16 * 1024 * 1024))
done
P="$GHIDRA_INSTALL_DIR/Ghidra/Processors/NS32016"
if [[ ! -e $P ]]; then ln -s "$MOD" "$P"; elif [[ $(readlink -f "$P") != "$MOD" ]]; then
	echo "warning: $P exists and is not this module" >&2; fi
"$HERE/build-jar.sh"

echo "== 3. decode differential (libopcodes${UNIDASM:+, MAME unidasm})"
[[ -x $W/slotdis ]] || "$HERE/build-slotdis.sh" "$W/slotdis"
[[ -x $W/dumpopc ]] || "$HERE/build-dumpopc.sh" "$W/dumpopc"
"$W/dumpopc" > "$W/opc.txt"
python3 "$HERE/gen_corpus.py" table "$W/opc.txt" "$W/table.bin" 5
python3 "$HERE/gen_corpus.py" random "$W/rand.bin" 200000 7
cat "$W/table.bin" "$W/rand.bin" > "$W/all.bin"
"$W/slotdis" "$W/all.bin" 48 > "$W/obj.txt"
MAME=()
if [[ -n $UNIDASM ]]; then
	"$UNIDASM" "$W/all.bin" -arch ns32000 -basepc 0 > "$W/mame.txt"
	MAME=(--mame "$W/mame.txt")
fi
for v in default 532; do
	lang=NS32016:LE:32:$([[ $v == 532 ]] && echo NS32532 || echo default)
	"$HERE/ghidra-script.sh" raw "$lang" "$W/all.bin" DumpSlots.java "$W/gh_$v.txt" 48
	echo "-- variant $v"
	python3 "$HERE/compare.py" "$W/gh_$v.txt" 48 "$W/all.bin" --variant $v --opc "$W/opc.txt" \
		--objdump "$W/obj.txt" "${MAME[@]}" --show 8 --details "$W/diff_$v" | tee "$W/compare_$v.txt" || fail=1
done

echo "== 4. every constructor is reached"
for v in default 532; do
	lang=NS32016:LE:32:$([[ $v == 532 ]] && echo NS32532 || echo default)
	spec=$MOD/data/languages/$([[ $v == 532 ]] && echo NS32532 || echo NS32016).slaspec
	"$HERE/ghidra-script.sh" raw "$lang" "$W/all.bin" Reach.java "$W/reach_$v.txt" 48
	python3 - "$spec" "$W/reach_$v.txt" "$v" <<'PY' || fail=1
import re, sys
lines = open(sys.argv[1]).read().split("\n")
cons = {i + 1 for i, l in enumerate(lines) if re.match(r"^(:|[A-Za-z0-9_]+:)", l)}
seen = {int(x) for x in open(sys.argv[2]).read().split()}
missing = sorted(cons - seen)
print(f"   {sys.argv[3]}: constructors reached {len(cons & seen)}/{len(cons)}")
for n in missing[:20]:
    print("   not reached:", n, lines[n - 1][:100])
sys.exit(1 if missing else 0)
PY
done

echo "== 5. p-code: emulator tests"
for v in default 532; do
	lang=NS32016:LE:32:$([[ $v == 532 ]] && echo NS32532 || echo default)
	mkdir -p "$W/emu_$v"
	if [[ -x ${NS32K_BINUTILS:-/nonexistent}/gas/as-new ]]; then
		python3 "$HERE/emu_tests.py" "$W/emu_$v" $v
		cmp "$W/emu_$v/emu.bin" "$HERE/golden/emu_$v.bin" && cmp "$W/emu_$v/tests.txt" "$HERE/golden/tests_$v.txt" ||
			{ echo "   test programs differ from test/golden/ (run test/update-golden.sh)"; fail=1; }
	else
		cp "$HERE/golden/emu_$v.bin" "$W/emu_$v/emu.bin"
		cp "$HERE/golden/tests_$v.txt" "$W/emu_$v/tests.txt"
	fi
	BASE_ADDR=0x1000 "$HERE/ghidra-script.sh" raw "$lang" "$W/emu_$v/emu.bin" EmuCheck.java \
		"$W/emu_$v/tests.txt" "$W/emu_$v/out.txt"
	echo "   $v: $(tail -1 "$W/emu_$v/out.txt")"
	grep -q ", 0 failed" "$W/emu_$v/out.txt" || { grep -v "^PASS" "$W/emu_$v/out.txt" | head -20; fail=1; }
done

if ((REAL)); then
	echo "== 6. real code (NetBSD/pc532)"
	"$HERE/fetch-real-samples.sh" "$W/samples"
	"$HERE/real-binaries.sh" "$W/real" "$W/samples" 100 || fail=1
	cat "$W/real/real/summary.txt"
fi

if ((fail)); then echo "FAILED"; exit 1; fi
echo "all tests passed"
