#!/usr/bin/env python3
"""Compare the decode of the first instruction of every slot between Ghidra and a reference
disassembler (GNU libopcodes ns32k via slotdis, or MAME unidasm ns32000).

  compare.py objdump <ghidra.txt> <ref.txt> <slot-size> <corpus.bin> [--show N] [--details out.txt]
  compare.py mame    <ghidra.txt> <ref.txt> <slot-size> <corpus.bin> [--show N] [--details out.txt]

ghidra.txt: lines "<slot> <length> <text>" (test/DumpSlots.java; length 0 = not decoded).
ref.txt:    objdump: lines "<slot> <length> <text>" (test/slotdis); mame: unidasm output of the corpus.
Every difference is put in a named bucket; 'explained' buckets are documented in GHIDRA-RARE.md.
"""
import re
import sys
from collections import Counter, defaultdict

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from ns32k_text import *  # noqa

OBJ_PROC = {"us": "UPSR", "dcr": "DCR", "bpc": "BPC", "dsr": "DSR", "car": "CAR", "fp": "FP", "sp": "SP", "sb": "SB",
            "usp": "USP", "cfg": "CFG", "psr": "PSR", "intbase": "INTBASE", "mod": "MOD"}
MMU32082 = {"BPR0": 0, "BPR1": 1, "PF0": 4, "PF1": 5, "SC": 8, "MSR": 10, "BCNT": 11, "PTB0": 12, "PTB1": 13, "EIA": 15}
MMU32532 = {"MCR": 9, "MSR": 10, "TEAR": 11, "PTB0": 12, "PTB1": 13, "IVAR0": 14, "IVAR1": 15}
MMU_OURS = dict(MMU32082)
OBJ_MMU = {"mcr": 9, "msr": 10, "tear": 11, "ptb0": 12, "ptb1": 13, "ivar0": 14, "ivar1": 15}
MAME_MMU = MMU32082
OBJ_MN = {"br": "but", "bn": "buf", "srb": "sutb", "srw": "sutw", "srd": "sutd", "snb": "sufb", "snw": "sufw",
          "snd": "sufd"}
NUMKIND_DISP = ("RET", "CXP", "RXP", "RETT")


def split_mn(text):
    p = text.split(None, 1)
    return p[0], (split_top(p[1]) if len(p) > 1 else [])


def load_pairs(path):
    d = {}
    for line in open(path, errors="replace"):
        p = line.rstrip("\n").split(" ", 2)
        d[int(p[0])] = (int(p[1]), p[2] if len(p) > 2 else "")
    return d


def load_mame(path, slot):
    lines = []
    for line in open(path, errors="replace"):
        m = re.match(r"\s*([0-9a-fA-F]+):\s+((?:[0-9a-f]{2} )*[0-9a-f]{2})?\s*(.*)$", line.rstrip("\n"))
        if m:
            lines.append((int(m.group(1), 16), m.group(3).strip()))
    d = {}
    for i, (a, t) in enumerate(lines):
        if a % slot == 0:
            nxt = lines[i + 1][0] if i + 1 < len(lines) else a + 1
            d[a // slot] = (nxt - a, re.sub(r"\s+", " ", t))
    return d


def render_ops(mn, ops, tool, pc):
    """Render the Ghidra operands in the reference syntax; returns (mnemonic, [operand strings or lists])."""
    base = mn.upper()
    asts = [parse_gh(o, pc) for o in ops]
    out = []
    for i, a in enumerate(asts):
        sz = imm_size(base, i)
        if a[0] == "NUM" and base in NUMKIND_DISP + ("ENTER",) and tool == "mame" and (base != "ENTER" or i == len(asts) - 1):
            out.append(disp_mame(a[1], "0"))
        elif tool == "objdump":
            out.append(r_obj(a, sz))
        else:
            out.append(r_mame(a, sz))
    return out


def norm_list(s):
    return frozenset(x.strip().upper() for x in s.strip("[]").split(",") if x.strip())


def canon_ref_ops(mn, ops, tool):
    out = []
    for o in ops:
        if (o.startswith("[") and o.endswith("]")) or (tool == "mame" and re.fullmatch(r"[A-Z](,[A-Z])*", o) and
                                                      mn.upper().startswith(("MOVS", "CMPS", "SKPS"))):
            out.append(("LIST", norm_list(o)))
        else:
            out.append(o)
    return out


def compare(gh_text, gh_len, ref_len, ref_text, tool, pc):
    gmn, gops = split_mn(gh_text)
    rtext = ref_text.strip()
    rp = rtext.split(None, 1)
    rmn = rp[0] if rp else ""
    rops = split_top(rp[1]) if len(rp) > 1 else []
    # mnemonics
    gm = gmn.lower()
    if tool == "objdump":
        gm = OBJ_MN.get(gm, gm)
        rm = rmn.lower()
    else:
        gm = gmn.upper()
        rm = re.sub(r"^(MOVST|CMPST|SKPST)[BWD]$", r"\1", rmn.upper())
    if gm != rm:
        return "mismatch-mnemonic", f"{gmn} vs {rmn}"
    # operands
    if gm in ("lpr", "spr") or gm.startswith(("lprb", "lprw", "lprd", "sprb", "sprw", "sprd")) or \
            re.match(r"^(lpr|spr)[bwd]$", gm.lower()):
        pass
    gr = render_ops(gmn, gops, tool, pc)
    rr = canon_ref_ops(rmn, rops, tool)
    n = max(len(gr), len(rr))
    if len(gr) != len(rr):
        return "mismatch-operand-count", f"{gh_text} | {ref_text}"
    is_branch = bool(re.fullmatch(r"B[A-Z]{1,2}|BSR|ACB[BWD]", gmn.upper()))
    for i, (g, r) in enumerate(zip(gr, rr)):
        # lists and names
        ga = parse_gh(gops[i], pc)
        if ga[0] == "ABS" and tool == "objdump" and isinstance(r, str):
            # binutils prints the displacement's decimal digits as a hexadecimal address (and, for a
            # negative displacement, its negation); the width of the printed value depends on the build
            m = re.fullmatch(r"@0x([0-9a-fA-F]+)", r)
            want = ga[1] if ga[1] >= 0 else -int(str(-ga[1]), 16)
            if ga[1] >= 0:
                want = int(str(ga[1]), 16)
            if not m or (int(m.group(1), 16) & 0xFFFFFFFF) != (want & 0xFFFFFFFF):
                return "mismatch-operand", f"{gh_text} | {ref_text}"
            continue
        if ga[0] == "PC" or (is_branch and i == len(gops) - 1 and ga[0] == "NUM"):
            m = re.fullmatch(r"0x([0-9a-fA-F]+)", r) if isinstance(r, str) else None
            if not m or (int(m.group(1), 16) & 0xFFFFFFFF) != (ga[1] & 0xFFFFFFFF):
                return "mismatch-operand", f"{gh_text} | {ref_text}"
            continue
        if ga[0] == "LIST":
            if tuple(sorted(ga[1])) != tuple(sorted(r[1])) if isinstance(r, tuple) else True:
                return "mismatch-list", f"{gh_text} | {ref_text}"
            continue
        if ga[0] == "WORD":
            gname = ga[1]
            if re.fullmatch(r"(LPR|SPR)[BWD]", gmn.upper()):
                rname = OBJ_PROC.get(r.lower(), r.upper()) if tool == "objdump" else r.upper()
                if rname != gname:
                    return "mismatch-procreg", f"{gh_text} | {ref_text}"
                continue
            if re.fullmatch(r"(LMR|SMR)", gmn.upper()):
                if tool == "objdump":
                    rn = OBJ_MMU.get(r.lower())
                    if rn is None:
                        return "mismatch-mmureg-undefined", f"{gh_text} | {ref_text}"
                else:
                    rn = MAME_MMU.get(r.upper())
                if MMU_OURS.get(gname) != rn:
                    return "mismatch-mmureg", f"{gh_text} | {ref_text}"
                continue
        if isinstance(g, str) and isinstance(r, str):
            n32 = lambda x: re.sub(r"@0xf{8}([0-9a-f]{8})", r"@0x\1", x.lower().replace(" ", ""))
            if n32(g) != n32(r):
                return "mismatch-operand", f"{gh_text} | {ref_text}"
        elif g != r:
            return "mismatch-operand", f"{gh_text} | {ref_text}"
    if gh_len != ref_len:
        return "mismatch-length", f"{gh_text} ({gh_len}) | {ref_text} ({ref_len})"
    return "match", ""


OPC = {}


def load_opc(path):
    for line in open(path):
        n, idb, tot, seed, ops = line.split()
        OPC.setdefault(n, ops)


def letters(mn):
    ops = OPC.get(mn.lower(), "-")
    if ops == "-":
        return []
    return [c for d, c in sorted(re.findall(r"(\d)([A-Za-z])", ops), key=lambda x: int(x[0]))]


SCC = re.compile(r"^s(eq|ne|cs|cc|hi|ls|gt|le|fs|fc|lo|hs|lt|ge|ut|uf|r|n)[bwd]$", re.I)
ONLY_532 = {"cinv", "dotf", "dotl", "polyf", "polyl", "scalbf", "scalbl", "logbf", "logbl"}
NAMES_532 = re.compile(r"\b(dcr|bpc|dsr|car|usp|cfg|undefined)\b", re.I)


def explain(st, tool, gtext, rtext, raw):
    """Name of the documented reason for a difference, or None."""
    mn = (rtext.split() or [""])[0].lower()
    if tool == "mame":
        mn = re.sub(r"^(movst|cmpst|skpst)[bwd]$", r"\1", mn)
    t = rtext.strip()
    ops = split_top(t[len(t.split()[0]):]) if t.split() else []
    lt = letters(mn)
    if st in ("mismatch-mmureg-undefined",):
        return "NS32082 MMU register numbers that binutils (NS32532 names) leaves undefined"
    if st == "mismatch-operand" and tool == "objdump" and mn == "sfsr" and "[" in t:
        return "binutils mis-decodes the index byte of SFSR (operand type 'f')"
    if st == "mismatch-operand" and tool == "objdump" and mn == "cxp":
        return "binutils prints CXP's link-table index as a code address"
    if st == "ref-only":
        if tool == "objdump":
            if "undefined" in t and mn.startswith(("movs", "cmps", "skps", "setcfg", "cinv")) and mn not in ONLY_532:
                return "reserved option bits (binutils prints 'undefined')"
            if mn in ("lfsr", "rdval", "wrval"):
                return "unused field of 19-bit opcode ids is not compared by binutils (only 16 bits are)"
            if "reserved" in t:
                return "reserved addressing mode 0x13 (binutils decodes it)"
            if "][" in t or re.search(r"\$[^,\s\[]*\[r\d:\w\]", t):
                return "scaled-index base that is itself an index or an immediate"
            if "$<undefined>" in t:
                return "immediate in an address or written operand"
            if mn in ONLY_532:
                return "NS32381/NS32532-only instruction"
            if (NAMES_532.search(t) or re.search(r"\b(mcr|tear|ivar[01])\b", t)) and mn.startswith(("lpr", "spr", "cinv", "lmr", "smr")):
                return "NS32532-only processor/MMU register"
            if SCC.match(mn) and any(o.startswith("$") for o in ops):
                return "immediate as the destination of Scc"
            for o, l in zip(ops, lt):
                if l == "A" and re.fullmatch(r"[rf]\d", o):
                    return "register in an address operand"
                if l in "IZ" and o.startswith("$"):
                    return "immediate in an address or written operand"
            if mn.endswith("l") or re.match(r"^(floor|round|trunc)l", mn) or mn in ("movlf",):
                for o in ops:
                    m = re.fullmatch(r"f(\d)", o)
                    if m and int(m.group(1)) % 2:
                        return "odd float register in a double-precision operand"
            if mn.startswith(("mov", "ext", "ins", "cvtp", "check", "index")) and any(o.startswith("$") for o in ops):
                return "immediate in an address or written operand"
    return None


def ref_invalid(text, tool):
    t = text.strip()
    if tool == "objdump":
        return bool(re.fullmatch(r"\d+", t)) or t == ""
    return t == ""


def slot_status(tool, gh, ref, i, slot):
    glen, gtext = gh[i]
    rlen, rtext = ref[i]
    ginv = glen == 0
    rinv = ref_invalid(rtext, tool)
    if ginv and rinv:
        return "both-invalid", "", gtext, rtext
    if ginv:
        return "ref-only", rtext, gtext, rtext
    if rinv:
        return "ghidra-only", gtext, gtext, rtext
    st, det = compare(gtext, glen, rlen, rtext, tool, i * slot)
    return st, det, gtext, rtext


def explain_mame(st, det, gtext, rtext, obj):
    """obj: (status, explanation) of the same slot against binutils."""
    mn = (rtext.split() or [""])[0].upper()
    if st == "ghidra-only" and gtext.startswith("CINV"):
        return "MAME's unidasm uses its external-MMU model, which has no CINV (the NS32532 model does)"
    if st == "mismatch-mmureg":
        return "MAME's unidasm uses the NS32082 MMU register names, not the NS32532 on-chip ones"
    if st == "mismatch-operand-count" and mn.startswith(("MOVS", "CMPS", "SKPS")):
        return "MAME prints no operand for empty string-instruction options"
    if st == "mismatch-operand" and mn.startswith(("MOVM", "CMPM")):
        return "MAME divides a negative MOVM/CMPM displacement as unsigned"
    if st in ("mismatch-operand", "mismatch-length") and mn == "SFSR":
        return "MAME also decodes the unused first general-operand field of SFSR"
    if st == "mismatch-operand" and re.search(r"0x[0-9A-F]{1,8}FFFFFFFF", rtext):
        return "MAME prints the low dword of 64-bit immediates as FFFFFFFF"
    if st == "ref-only":
        if obj[0] == "both-invalid":
            return "undefined in binutils and the module, decoded by MAME (no validation of size/reserved fields)"
        if obj[1]:
            return "MAME decodes it like binutils: " + obj[1]
    if st == "mismatch-operand" and obj[1]:
        return "MAME agrees with binutils: " + obj[1]
    return None


def main():
    args = [a for a in sys.argv[1:]]
    opts = {}
    pos = []
    k = 0
    while k < len(args):
        if args[k].startswith("--"):
            opts[args[k]] = args[k + 1]
            k += 2
        else:
            pos.append(args[k])
            k += 1
    ghf, slot, corpus = pos[0], int(pos[1]), pos[2]
    if opts.get("--variant") == "532":
        MMU_OURS.clear()
        MMU_OURS.update(MMU32532)
    show = int(opts.get("--show", 10))
    if "--opc" in opts:
        load_opc(opts["--opc"])
    gh = load_pairs(ghf)
    data = open(corpus, "rb").read()
    refs = {}
    if "--objdump" in opts:
        refs["objdump"] = load_pairs(opts["--objdump"])
    if "--mame" in opts:
        refs["mame"] = load_mame(opts["--mame"], slot)
    unexplained_total = 0
    objres = {}
    for tool in ("objdump", "mame"):
        if tool not in refs:
            continue
        ref = refs[tool]
        buckets = Counter()
        explained = Counter()
        examples = defaultdict(list)
        exex = defaultdict(list)
        for i in sorted(gh):
            if i not in ref:
                continue
            st, det, gtext, rtext = slot_status(tool, gh, ref, i, slot)
            why = None
            if st not in ("match", "both-invalid"):
                if tool == "objdump":
                    why = explain(st, tool, gtext, rtext, None)
                else:
                    why = explain_mame(st, det, gtext, rtext, objres.get(i, ("both-invalid", None)))
            if tool == "objdump":
                objres[i] = (st, why)
            if why:
                explained[why] += 1
                hexb = data[i * slot:i * slot + 12].hex()
                exex[why].append(f"{i} {hexb} :: {gtext} | {rtext}")
                continue
            buckets[st] += 1
            if st not in ("match", "both-invalid"):
                hexb = data[i * slot:i * slot + 12].hex()
                examples[st].append(f"{i} {hexb} :: {det}")
        total = sum(buckets.values()) + sum(explained.values())
        print(f"{tool}: {total} slots: " + ", ".join(f"{k} {v}" for k, v in sorted(buckets.items(), key=lambda kv: -kv[1])
                                                    if k in ("match", "both-invalid")) +
              f", explained {sum(explained.values())}, unexplained {sum(v for k, v in buckets.items() if k not in ('match', 'both-invalid'))}")
        for k, v in sorted(explained.items(), key=lambda kv: -kv[1]):
            print(f"      {v:7} {k}")
        for k, lines in examples.items():
            unexplained_total += len(lines)
            print(f"-- UNEXPLAINED {k} ({len(lines)})")
            for l in lines[:show]:
                print("   ", l)
        if "--details" in opts:
            with open(opts["--details"] + "." + tool, "w") as f:
                for k, lines in exex.items():
                    f.write(f"== explained: {k} ({len(lines)})\n" + "\n".join(lines) + "\n")
                for k, lines in examples.items():
                    f.write(f"== {k} ({len(lines)})\n" + "\n".join(lines) + "\n")
    sys.exit(1 if unexplained_total else 0)


main()
