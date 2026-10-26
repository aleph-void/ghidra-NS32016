"""Parsing of Ghidra / GNU objdump / MAME unidasm NS32000 disassembly text into a common form.

Ghidra's text is parsed into an operand AST (our own format is regular); the AST is then rendered in
the two reference syntaxes and compared as strings, so ambiguities of the reference syntaxes
(MAME prints immediates, absolute addresses and PC-relative addresses all as 0x...) never matter.
"""
import re
import struct

MASK = {"B": 0xFF, "W": 0xFFFF, "D": 0xFFFFFFFF, "Q": 0xFFFFFFFFFFFFFFFF}


def sext(v, bits):
    v &= (1 << bits) - 1
    return v - (1 << bits) if v >> (bits - 1) else v


def split_top(s):
    out, depth, cur = [], 0, ""
    for ch in s:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


NUM = r"-?0x[0-9a-fA-F]+"


def num(s):
    return int(s, 16) if "0x" in s.lower() else int(s)


def parse_gh(s, pc):
    """Ghidra operand text -> AST tuple."""
    s = s.strip()
    if s == "TOS":
        return ("TOS",)
    m = re.fullmatch(r"R([0-7])[bw]?", s)
    if m:
        return ("R", int(m.group(1)))
    m = re.fullmatch(r"[FL]([0-7])", s)
    if m:
        return ("F", int(m.group(1)))
    m = re.fullmatch("#(" + NUM + ")", s)
    if m:
        return ("IMM", num(m.group(1)))
    m = re.fullmatch(r"(.*)\[R([0-7]):([BWDQ])\]", s)
    if m:
        return ("IDX", parse_gh(m.group(1), pc), int(m.group(2)), m.group(3))
    m = re.fullmatch(r"\*\+(" + NUM + ")", s)
    if m:
        return ("PC", pc + num(m.group(1)))
    m = re.fullmatch("@(" + NUM + ")", s)
    if m:
        return ("ABS", num(m.group(1)))
    m = re.fullmatch(r"EXT\((" + NUM + r")\)\+(" + NUM + ")", s)
    if m:
        return ("EXT", num(m.group(1)), num(m.group(2)))
    m = re.fullmatch("(" + NUM + r")\((" + NUM + r")\((FP|SP|SB)\)\)", s)
    if m:
        return ("MEMREL", num(m.group(1)), num(m.group(2)), m.group(3))
    m = re.fullmatch("(" + NUM + r")\((R[0-7]|FP|SP|SB)\)", s)
    if m:
        return ("MEM", num(m.group(1)), m.group(2))
    if re.fullmatch(NUM, s):
        return ("NUM", num(s))
    m = re.fullmatch(r"\[(.*)\]", s)
    if m:
        items = [x.strip().upper() for x in m.group(1).split(",") if x.strip()]
        return ("LIST", frozenset(items))
    return ("WORD", s.upper())


# ------------------------------------------------------------------ operand sizes of immediates
INT_BASES = set("""ADD ADDC SUB SUBC CMP BIC MOV OR AND XOR TBIT ADDQ CMPQ ACB MOVQ ADJSP CASE BICPSR BISPSR
 LPR SPR NEG NOT ABS COM SUBP ADDP CBIT CBITI SBIT SBITI IBIT MUL MEI DEI QUO REM MOD DIV CHECK INDEX EXT
 INS FFS MOVM CMPM INSS EXTS MOVSU MOVUS""".split())


def imm_size(mn, idx):
    """Size letter (B W D F L) of operand idx of instruction mn, used to interpret immediates."""
    m = mn.upper()
    if m in ("MOVXBW", "MOVZBW"):
        return "B" if idx == 0 else "W"
    if m in ("MOVXBD", "MOVXWD", "MOVZBD", "MOVZWD"):
        return m[4] if idx == 0 else "D"
    if m == "MOVLF":
        return "L" if idx == 0 else "F"
    if m == "MOVFL":
        return "F" if idx == 0 else "L"
    if m in ("LFSR", "SFSR"):
        return "D"
    r = re.fullmatch(r"MOV([BWD])([FL])", m)
    if r:
        return r.group(1) if idx == 0 else r.group(2)
    r = re.fullmatch(r"(ROUND|TRUNC|FLOOR)([FL])([BWD])", m)
    if r:
        return r.group(2) if idx == 0 else r.group(3)
    r = re.fullmatch(r"(ADD|SUB|MUL|DIV|MOV|CMP|NEG|ABS|POLY|DOT|SCALB|LOGB)([FL])", m)
    if r:
        return r.group(2)
    r = re.fullmatch(r"(ASH|LSH|ROT)([BWD])", m)
    if r:
        return "B" if idx == 0 else r.group(2)
    r = re.fullmatch(r"([A-Z]+)([BWD])", m)
    if r:
        return r.group(2)
    return "D"


# ------------------------------------------------------------------ renderers
def fmt_g(v):
    return "%g" % v


def float_text_objdump(bits, size):
    bits &= 0xFFFFFFFF if size == "F" else 0xFFFFFFFFFFFFFFFF
    if size == "F":
        exp = (bits >> 23) & 0xFF
        man = bits & 0x7FFFFF
        if exp == 0xFF or (exp == 0 and man != 0):
            return "<<invalid float 0x%.8x>>" % bits
        return "$" + fmt_g(struct.unpack("<f", struct.pack("<I", bits))[0])
    exp = (bits >> 52) & 0x7FF
    man = bits & ((1 << 52) - 1)
    if exp == 0x7FF or (exp == 0 and man != 0):
        return "<<invalid double 0x%.8x%.8x>>" % (bits >> 32, bits & 0xFFFFFFFF)
    return "$" + fmt_g(struct.unpack("<d", struct.pack("<Q", bits))[0])


def r_obj(a, size=None):
    t = a[0]
    if t == "R":
        return "r%d" % a[1]
    if t == "F":
        return "f%d" % a[1]
    if t == "TOS":
        return "tos"
    if t == "IMM":
        if size in ("F", "L"):
            return float_text_objdump(a[1], size)
        bits = {"B": 8, "W": 16, "D": 32}.get(size, 32)
        return "$%d" % sext(a[1], bits)
    if t == "MEM":
        return "%d(%s)" % (a[1], a[2].lower())
    if t == "MEMREL":
        return "%d(%d(%s))" % (a[1], a[2], a[3].lower())
    if t == "ABS":
        # binutils prints the decimal digits of the displacement as a hexadecimal address
        d = a[1]
        if d >= 0:
            return "@0x%s" % d
        return "@0x%x" % ((-int(str(-d), 16)) & 0xFFFFFFFFFFFFFFFF)
    if t == "EXT":
        return "EXT(%d) + %d" % (a[1], a[2])
    if t == "PC":
        return "0x%x" % (a[1] & 0xFFFFFFFFFFFFFFFF)
    if t == "IDX":
        b = a[1]
        if b[0] == "R" and size in ("F", "L"):
            b = ("F", b[1])
        return "%s[r%d:%s]" % (r_obj(b, size), a[2], a[3].lower())
    if t == "NUM":
        return "%d" % a[1]
    if t == "LIST":
        return ("LIST", a[1])
    return a[1].lower()


def sh(v):
    return ("-0x%X" % -v) if v < 0 else "0x%X" % v


def disp_mame(v, zero=""):
    return sh(v) if v else zero


def r_mame(a, size=None):
    t = a[0]
    if t == "R":
        return "R%d" % a[1]
    if t == "F":
        return "F%d" % a[1]
    if t == "TOS":
        return "TOS"
    if t == "IMM":
        return "0x%X" % (a[1] & MASK[{"F": "D", "L": "Q"}.get(size, size or "D")])
    if t == "MEM":
        return "%s(%s)" % (disp_mame(a[1]), a[2])
    if t == "MEMREL":
        return "%s(%s(%s))" % (disp_mame(a[1]), disp_mame(a[2]), a[3])
    if t == "ABS":
        return "@0x%X" % (a[1] & 0xFFFFFFFF)
    if t == "EXT":
        d1 = disp_mame(a[1], "0")
        if a[2] < 0:
            return "EXT(%s) - 0x%X" % (d1, -a[2])
        if a[2] > 0:
            return "EXT(%s) + 0x%X" % (d1, a[2])
        return "EXT(%s)" % d1
    if t == "PC":
        return "0x%X" % (a[1] & 0xFFFFFFFF)
    if t == "IDX":
        b = a[1]
        if b[0] == "R" and size in ("F", "L"):
            b = ("F", b[1])
        return "%s[R%d:%s]" % (r_mame(b, size), a[2], a[3])
    if t == "NUM":
        return "%d" % a[1]
    if t == "LIST":
        return ("LIST", a[1])
    return a[1]
