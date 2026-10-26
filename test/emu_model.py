"""An independent Python model of NS32000 integer arithmetic, written from the instruction set
definitions, used to generate randomised emulator cases (see emu_tests.py).  R0 is the first
(source) operand and R1 the second (destination) operand; flag results use the PSR names C L F Z N."""
import random

BITS = {"b": 8, "w": 16, "d": 32}


def mask(s):
    return (1 << BITS[s]) - 1


def sx(v, s):
    n = BITS[s]
    v &= (1 << n) - 1
    return v - (1 << n) if v >> (n - 1) else v


def tdiv(a, b):  # truncating division
    q = abs(a) // abs(b)
    return q if (a < 0) == (b < 0) else -q


def model(op, s, a, b, c):
    """Return (result or None, flags dict) for destination b, source a, carry-in c."""
    m = mask(s)
    sign = 1 << (BITS[s] - 1)
    a &= m
    b &= m
    fl = {}
    if op == "add":
        r = (a + b) & m
        fl = dict(C=int(a + b > m), F=int(((a ^ r) & (b ^ r) & sign) != 0))
    elif op == "addc":
        r = (a + b + c) & m
        fl = dict(C=int(a + b + c > m), F=int(((a ^ r) & (b ^ r) & sign) != 0))
    elif op == "sub":
        r = (b - a) & m
        fl = dict(C=int(b < a), F=int(((a ^ b) & (b ^ r) & sign) != 0))
    elif op == "subc":
        r = (b - a - c) & m
        fl = dict(C=int(b < a + c), F=int(((a ^ b) & (b ^ r) & sign) != 0))
    elif op == "cmp":
        return None, dict(Z=int(a == b), N=int(sx(a, s) > sx(b, s)), L=int(a > b))
    elif op == "and":
        r = a & b
    elif op == "or":
        r = a | b
    elif op == "xor":
        r = a ^ b
    elif op == "bic":
        r = b & ~a & m
    elif op == "mov":
        r = a
    elif op == "com":
        r = ~a & m
    elif op == "not":
        r = a ^ 1
    elif op == "neg":
        r = (-a) & m
        fl = dict(C=int(a != 0), F=int(a == sign))
    elif op == "abs":
        r = a if a == sign else abs(sx(a, s)) & m
        fl = dict(F=int(a == sign))
    elif op == "mul":
        r = (a * b) & m
    elif op in ("quo", "rem", "div", "mod"):
        x, y = sx(b, s), sx(a, s)      # dividend b, divisor a
        if y == 0:
            return "trap", {}
        if op == "quo":
            r = tdiv(x, y) & m
        elif op == "rem":
            r = (x - y * tdiv(x, y)) & m
        elif op == "div":
            r = (x // y) & m
        else:
            r = (x % y) & m
    elif op in ("lsh", "ash", "rot"):
        cnt = sx(a, "b")                # the count is always a signed byte
        n = BITS[s]
        if op == "rot":
            k = cnt % n
            r = ((b << k) | (b >> (n - k))) & m if k else b
        elif cnt >= 0:
            r = (b << cnt) & m if cnt < 64 else 0
        elif op == "lsh":
            r = (b >> -cnt) & m if -cnt < 64 else 0
        else:
            r = (sx(b, s) >> min(-cnt, 63)) & m
    else:
        raise ValueError(op)
    return r, fl


def cases(seed, per_op):
    rnd = random.Random(seed)
    edge = {"b": [0, 1, 0x7F, 0x80, 0xFF, 0xFE], "w": [0, 1, 0x7FFF, 0x8000, 0xFFFF, 0xFFFE],
            "d": [0, 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 0xFFFFFFFE]}
    out = []
    ops = ["add", "addc", "sub", "subc", "cmp", "and", "or", "xor", "bic", "mov", "com", "not", "neg", "abs",
           "mul", "quo", "rem", "div", "mod", "lsh", "ash", "rot"]
    for op in ops:
        for s in "bwd":
            for k in range(per_op):
                n = BITS[s]
                pick = lambda: rnd.choice(edge[s]) if rnd.random() < 0.4 else rnd.getrandbits(n)
                a, b = pick(), pick()
                if op in ("lsh", "ash", "rot"):
                    a = rnd.choice([0, 1, 2, 7, 8, 15, 16, 31, 32, 33, 0xFF, 0xFE, 0xF8, 0xE0, 0xDF, rnd.getrandbits(8)])
                c = rnd.getrandbits(1)
                r, fl = model(op, s, a, b, c)
                if r == "trap":
                    continue
                out.append((op, s, a, b, c, r, fl))
    return out
