#!/usr/bin/env python3
"""Compare Ghidra's disassembly of a real binary with GNU objdump's, instruction by instruction at the
addresses Ghidra disassembled.

  real_compare.py <ghidra.lst> <objdump-D-output> [--opc opc.txt] [--show N]

ghidra.lst lines: "<hex address> <length> <text>" (test/RealCheck.java).  The objdump listing comes from
`objdump -d` on the same file (or `-D -b binary --adjust-vma`).
"""
import re
import sys
from collections import Counter

sys.path.insert(0, __file__.rsplit("/", 1)[0])
src = open(__file__.rsplit("/", 1)[0] + "/compare.py").read().replace("\nmain()\n", "\n")
ns = {"__file__": __file__.rsplit("/", 1)[0] + "/compare.py"}
exec(compile(src, "compare", "exec"), ns)
compare, explain, load_opc = ns["compare"], ns["explain"], ns["load_opc"]


def load_list(path):
    """slotdis list output: '<hex address> <length> <text>'."""
    insns = {}
    for line in open(path, errors="replace"):
        a, ln, text = line.rstrip("\n").split(" ", 2)
        insns[int(a, 16)] = [int(a, 16), int(ln), text]
    return insns


def load_objdump(path):
    insns = {}
    prev = None
    for line in open(path, errors="replace"):
        m = re.match(r"\s*([0-9a-f]+):\t((?:[0-9a-f]{2} )+)\s*(?:\t(.*))?$", line.rstrip("\n"))
        if not m:
            continue
        addr = int(m.group(1), 16)
        text = (m.group(3) or "").strip()
        if text:
            insns[addr] = [addr, len(m.group(2).split()), text]
            prev = addr
        elif prev is not None:
            insns[prev][1] += len(m.group(2).split())
    return insns


def main():
    args = sys.argv[1:]
    show = 10
    if "--variant" in args and args[args.index("--variant") + 1] == "532":
        ns["MMU_OURS"].clear()
        ns["MMU_OURS"].update(ns["MMU32532"])
    if "--opc" in args:
        load_opc(args[args.index("--opc") + 1])
    if "--show" in args:
        show = int(args[args.index("--show") + 1])
    gh = [l.rstrip("\n").split(" ", 2) for l in open(args[0])]
    ref = load_list(args[1]) if "--list" in args else load_objdump(args[1])
    c = Counter()
    ex = {}
    for a, ln, text in gh:
        addr, ln = int(a, 16), int(ln)
        r = ref.get(addr)
        if r is None:
            c["no-reference-instruction"] += 1
            continue
        st, det = compare(text, ln, r[1], r[2], "objdump", addr)
        if st != "match":
            why = explain(st, "objdump", text, r[2], None)
            st = "explained: " + why if why else st
        c[st] += 1
        if st != "match":
            ex.setdefault(st, []).append(f"{addr:x} {text} | {r[2]}")
    tot = sum(c.values())
    print(f"{tot} Ghidra instructions compared with objdump")
    for k, v in c.most_common():
        print(f"  {v:8} {k}")
    for k, v in ex.items():
        if not k.startswith("explained"):
            print("--", k)
            for l in v[:show]:
                print("   ", l)
    unexplained = sum(v for k, v in c.items() if k != "match" and not k.startswith("explained"))
    sys.exit(1 if unexplained else 0)


main()
