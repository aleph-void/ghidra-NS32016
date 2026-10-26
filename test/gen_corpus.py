#!/usr/bin/env python3
"""Instruction corpora for the NS32016 decode differential.  Every corpus is a file of fixed-size
slots; the first instruction of each slot is decoded by every tool.

  gen_corpus.py random <out.bin> <count> <seed>
      uniformly random 18-byte prefixes
  gen_corpus.py table <opc.txt> <out.bin> <seed>
      every entry of GNU binutils' NS32000 opcode table (dumpopc output) with all 32 x 32 values of
      the two 5-bit general-addressing-mode fields (single-operand entries: all 32), random
      index bytes, displacements and immediates after the opcode
  gen_corpus.py modes <out.bin> <seed>
      every opcode-table entry x every (gen1, gen2) mode pair x all 4 index-base choices is covered
      by 'table'; this adds all 256 index-byte values for every scaled-index mode
"""
import random
import sys

SLOT = 48
PREFIX = 20
NOP = 0xA2


def slot(b):
    b = bytes(b[:PREFIX])
    return b + bytes([NOP]) * (SLOT - len(b))


def opcode_bytes(seed, idbits, total):
    nb = (total + 7) // 8
    return [(seed >> (8 * i)) & 0xFF for i in range(nb)]


def main():
    mode = sys.argv[1]
    if mode == "random":
        out, n, seed = sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
        r = random.Random(seed)
        with open(out, "wb") as f:
            for _ in range(n):
                f.write(slot(bytes(r.randrange(256) for _ in range(18))))
    elif mode == "table":
        opc, out, seed = sys.argv[2], sys.argv[3], int(sys.argv[4])
        r = random.Random(seed)
        n = 0
        with open(out, "wb") as f:
            for line in open(opc):
                name, idbits, total, seedhex, operands = line.split()
                idbits, total, sd = int(idbits), int(total), int(seedhex, 16)
                ngen = sum(operands.count(c) for c in "FLBWDAIZf")
                gens = [] if ngen == 0 else ([2] if "f" in operands else [1] if ngen == 1 else [1, 2])
                if total == 8:
                    # register lists (SAVE RESTORE ENTER EXIT) get every list value
                    vals = range(256) if any(c in operands for c in "Uu") else range(4)
                    for v in vals:
                        tail = bytes(r.randrange(256) for _ in range(PREFIX - 2))
                        f.write(slot(bytes([sd & 0xFF, v if len(vals) == 256 else r.randrange(256)]) + tail))
                        n += 1
                    continue
                if any(c in operands for c in "SO"):
                    # string options and SETCFG lists: every value of the option byte (and of bit 15 for SETCFG)
                    for hi in ((0x00, 0x80) if "O" in operands else (None,)):
                        for v in range(256):
                            w = [(sd >> (8 * i)) & 0xFF for i in range(3)]
                            if hi is not None:
                                w[1] = (w[1] & 0x7F) | hi
                            w[2] = v
                            f.write(slot(bytes(w) + bytes(r.randrange(256) for _ in range(PREFIX - 3))))
                            n += 1
                    continue
                nb = total // 8
                off = nb - 2                      # byte offset of the 16-bit opcode word holding the gen fields
                fixed = (1 << idbits) - 1
                combos = [(a, b) for a in (range(32) if 1 in gens else [None]) for b in (range(32) if 2 in gens else [None])]
                shorts = range(16) if any(c in operands for c in "PM") else [None]
                combos = [(g1, g2, sh) for (g1, g2) in combos for sh in shorts]
                for g1, g2, sh in combos:
                    word = (sd >> (8 * off)) & 0xFFFF
                    fixedw = (fixed >> (8 * off)) & 0xFFFF
                    free = ~fixedw & 0xFFFF
                    if g1 is not None:
                        free &= ~(0x1F << 11)
                    if g2 is not None:
                        free &= ~(0x1F << 6)
                    word = (word & ~free) | (r.randrange(1 << 16) & free)
                    if sh is not None:
                        word = (word & ~(0xF << 7)) | (sh << 7)
                    if g1 is not None:
                        word = (word & ~(0x1F << 11)) | (g1 << 11)
                    if g2 is not None:
                        word = (word & ~(0x1F << 6)) | (g2 << 6)
                    w = [(sd >> (8 * i)) & 0xFF for i in range(off)] + [word & 0xFF, word >> 8]
                    tail = bytes(r.randrange(256) for _ in range(PREFIX - len(w)))
                    f.write(slot(bytes(w) + tail))
                    n += 1
        print(n, "slots", file=sys.stderr)
    else:
        sys.exit(__doc__)


main()
