# NS32016 / NS32532 (National Semiconductor Series 32000) for Ghidra

SLEIGH processor module for the NS32016 family: the NS32016 with NS32081 FPU and NS32082 MMU
registers (language `NS32016:LE:32:default`) and the NS32532 with NS32381 FPU and on-chip MMU
(`NS32016:LE:32:NS32532`), plus a loader for NetBSD/pc532 a.out programs.

Original module by Ray Bellis ([raybellis/ghidra-NS32016](https://github.com/raybellis/ghidra-NS32016),
"WIP NS32016 disassembler for Ghidra for learning Sleigh", Apache-2.0). This fork keeps his history and
license; see `CREDITS.md`. Verification results, the test suite and every known gap are in
`GHIDRA-RARE.md`.

## Install

Download the zip for your Ghidra version from the
[Releases page](https://github.com/aleph-void/ghidra-NS32016/releases) and install it with
*File > Install Extensions*, or build it yourself:

    GHIDRA_INSTALL_DIR=/path/to/ghidra gradle buildExtension

The module builds against Ghidra 12.1.3, 12.1.4 and 12.2.

## Status of the upstream limitations

The upstream module was explicitly work in progress. What it listed or showed, and where it stands:

| Upstream state | Now |
|---|---|
| README was the unmodified template title ("68000") | fixed: this file |
| No p-code (every constructor `{}`), so no flags, no data flow, no decompiler output | fixed: complete semantics, see `GHIDRA-RARE.md` |
| Catch-all `UNK` constructor decoded every unknown byte as a 1-byte instruction | fixed: unknown encodings are bad instructions |
| `R2` shown for `R3`: the register attach list was `R0 R1 R3 R3 ...` | fixed |
| Scaled-index modes exported 0, `ACB` branched on `Z`, `RET`/`ENTER`/`SAVE`/... ignored their operands | fixed |
| One displacement table shared by both operands, so the second operand's extension was read from the wrong place | fixed |
| Formats 9-14 (FPU, MMU, string/bit-field extensions) missing | fixed |
| Condition code names (`H`, `T`, `F`) not those of the instruction set | fixed |
| Stack pointers named `SP0`/`SP1`, flags as bit ranges of a 16-bit `PSR` | changed: `SP` is the live stack pointer (`SPB` the other, swapped with `PSR.S`), flags are separate registers |
| No calling convention beyond a stub, `R1`-`R7` all callee-saved | fixed: GCC/NetBSD convention |
| No loader | added for NetBSD/pc532 a.out |
| Remaining | NS32381-only POLY/DOT/SCALB/LOGB and the hardware operations are pcodeops, see `GHIDRA-RARE.md` |
