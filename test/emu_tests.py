#!/usr/bin/env python3
"""Hand-computed p-code tests for the NS32016 module (run in Ghidra's emulator by EmuCheck.java).

  emu_tests.py <workdir> [default|532]

emu_cases.py lists short instruction sequences with initial register/memory values and the
expected registers, flags and memory afterwards; the expectations are worked out by hand from the
NS32000 instruction set definitions, never from the module's own output.  emu_model.py adds
randomised vectors checked against an independent Python model of the integer instructions.
The sequences are assembled with GNU as for ns32k (a line '@raw HEX... ; text' is emitted as
bytes), linked at 0x1000 and written as emu.bin; tests.txt has one line per test.

Tools (override with the environment): NS32K_BINUTILS (a GNU binutils 2.45 built for
--target=ns32k-netbsd with the ns32k BFD back end re-enabled), or NS32K_AS, NS32K_LD,
NS32K_OBJCOPY, NS32K_NM, NS32K_OBJDUMP individually.
"""
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
HOME = os.path.expanduser("~")
BU = os.environ.get("NS32K_BINUTILS", f"{HOME}/.cache/ghidra-rare-scratch/tools/bu-ns32k")
AS = os.environ.get("NS32K_AS", f"{BU}/gas/as-new")
LD = os.environ.get("NS32K_LD", f"{BU}/ld/ld-new")
OBJCOPY = os.environ.get("NS32K_OBJCOPY", f"{BU}/binutils/objcopy")
NM = os.environ.get("NS32K_NM", f"{BU}/binutils/nm-new")
OBJDUMP = os.environ.get("NS32K_OBJDUMP", f"{BU}/binutils/objdump")
BASE = 0x1000

VARIANT = sys.argv[2] if len(sys.argv) > 2 else "default"   # "default" (NS32016) or "532" (NS32532)
tests = []    # (name, asm, init, expect)
vectors = []  # (name, asm, [(init, expect), ...])


def T(name, asm, init="", expect="", only=None):
    """One test: asm lines, 'R0=5,C=1' style initial state and expected state.  only="default" or
    only="532" restricts the test to one language variant."""
    if only is None or only == VARIANT:
        tests.append((name, asm.strip("\n"), init, expect))


def cond_tests():
    # flags order: C L F Z N.  A branch is taken when the condition holds; the instruction after it
    # sets R2 to 1, so R2 == 0 means taken.
    table = {
        "eq": lambda C, L, F, Z, N: Z, "ne": lambda C, L, F, Z, N: not Z, "cs": lambda C, L, F, Z, N: C,
        "cc": lambda C, L, F, Z, N: not C, "hi": lambda C, L, F, Z, N: L, "ls": lambda C, L, F, Z, N: not L,
        "gt": lambda C, L, F, Z, N: N, "le": lambda C, L, F, Z, N: not N, "fs": lambda C, L, F, Z, N: F,
        "fc": lambda C, L, F, Z, N: not F, "lo": lambda C, L, F, Z, N: (not L) and (not Z),
        "hs": lambda C, L, F, Z, N: L or Z, "lt": lambda C, L, F, Z, N: (not N) and (not Z),
        "ge": lambda C, L, F, Z, N: N or Z,
    }
    flagsets = [dict(C=0, L=0, F=0, Z=0, N=0), dict(C=1, L=1, F=1, Z=1, N=1), dict(C=1, L=0, F=0, Z=1, N=0),
                dict(C=0, L=1, F=1, Z=0, N=1)]
    for cc, fn in table.items():
        for k, fl in enumerate(flagsets):
            taken = bool(fn(**fl))
            init = ",".join(f"{f}={v}" for f, v in fl.items())
            T(f"b{cc}_{k}", f"b{cc} 1f\n movqd 1,r2\n1:", init, f"R2={0 if taken else 1}")
            T(f"s{cc}_{k}", f"s{cc}b r3", init + ",R3=ff", f"R3={'01' if taken else '00'}")


def model_vectors():
    import emu_model
    groups = {}
    for op, sz, a, b, c, r, fl in emu_model.cases(20260726, 12):
        init = f"R0={a:x},R1={b:x}" + (f",C={c}" if op in ("addc", "subc") else "")
        exp = []
        if r is not None:
            exp.append(f"R1={r:x}")
        exp += [f"{k}={v}" for k, v in fl.items()]
        groups.setdefault((op, sz), []).append((init, ",".join(exp)))
    for (op, sz), vs in groups.items():
        vectors.append((f"m_{op}_{sz}", f"{op}{sz} r0,r1", vs))


exec(open(os.path.join(HERE, "emu_cases.py")).read())
model_vectors()


def main():
    work = sys.argv[1]
    os.makedirs(work, exist_ok=True)
    src = ["\t.text", "start:"]
    snippets = [(n, a) for n, a, _, _ in tests] + [(n, a) for n, a, _ in vectors]
    for name, asm in snippets:
        src.append(f"t_{name}:")
        for line in asm.splitlines():
            line = line.strip()
            if line.startswith("@raw"):
                body = line[4:].split(";")[0].split()
                src.append("\t.byte " + ",".join("0x" + b for b in body))
            else:
                src.append("\t" + line)
        src.append(f"e_{name}:")
        src.append("\tnop")
    open(f"{work}/emu.s", "w").write("\n".join(src) + "\n")
    subprocess.run([AS, "-o", f"{work}/emu.o", f"{work}/emu.s"], check=True)
    subprocess.run([LD, "-Ttext", hex(BASE), "-N", "-o", f"{work}/emu.out", f"{work}/emu.o"], check=True)
    subprocess.run([OBJCOPY, "-O", "binary", f"{work}/emu.out", f"{work}/emu.bin"], check=True)
    syms = {}
    for line in subprocess.run([NM, f"{work}/emu.out"], capture_output=True, text=True, check=True).stdout.splitlines():
        p = line.split()
        if len(p) == 3:
            syms[p[2]] = int(p[0], 16)
    with open(f"{work}/emu.lst", "w") as f:
        f.write(subprocess.run([OBJDUMP, "-d", f"{work}/emu.out"], capture_output=True, text=True).stdout)

    def sub(s):
        return re.sub(r"\{([^}]+)\}", lambda m: "%x" % (eval(m.group(1), {"__builtins__": {}}, syms) & 0xFFFFFFFF), s)

    count = 0
    with open(f"{work}/tests.txt", "w") as f:
        for name, asm, init, expect in tests:
            f.write(f"{name} {syms['t_' + name]:x} {syms['e_' + name]:x} {sub(init) or '-'} {sub(expect) or '-'}\n")
            count += 1
        for name, asm, vs in vectors:
            for k, (init, expect) in enumerate(vs):
                f.write(f"{name}_{k} {syms['t_' + name]:x} {syms['e_' + name]:x} {init or '-'} {expect or '-'}\n")
                count += 1
    print(count, "tests")


main()
