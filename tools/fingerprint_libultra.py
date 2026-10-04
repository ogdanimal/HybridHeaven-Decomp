#!/usr/bin/env python3
"""Recover libultra function names by fingerprinting against a reference decomp.

Hybrid Heaven links libultra 2.0H, and so does the mnsg (Mystical Ninja
Starring Goemon) decompilation. Both are IDO-built N64 titles, so the library's
object code is byte-identical between them apart from operands the linker
relocated. Masking those operands away leaves an instruction stream that
identifies a function exactly.

Writes `config/<ver>/symbol_addrs/libultra_syms.txt`, which splat reads
alongside the hand-maintained `symbol_addrs.txt`. Regenerating is only needed
when the reference decomp or the .text split changes; the output is committed.

Usage:
    uv run python tools/fingerprint_libultra.py [--ref PATH] [--version usa]
    uv run python tools/fingerprint_libultra.py --report   # don't write, just print
"""
import argparse
import re
import struct
import sys
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_REF = REPO.parent / "Goemon64Recomp/lib/mnsg"

# Both games' static segment maps ROM->VRAM with the same delta.
DELTA = 0x7FFFF400

# .text below this ROM offset is game code; above it is the linked library.
#
# 0x26F00, not the 0x273F0 where COP0 instructions first appear: osSendMesg
# matches exactly at 0x26F00 and osRecvMesg just above it, and the translation
# unit sizes change regime there too -- 0x4220, 0x1F10 below it against 0x150,
# 0x1A0, 0x200, 0x200 above. Three TUs of libultra sit below the first COP0 use.
LIBULTRA_ROM_START = 0x26F00
LIBULTRA_VRAM_START = LIBULTRA_ROM_START + DELTA

# Functions whose code is identical to another library function once relocated
# operands are masked, resolved by external evidence. Keyed by HH vram.
#
# Every entry here is justified by something the fingerprint alone cannot see:
# a confirmed caller, the global the function touches, or an adjacency that is
# reproduced exactly in the reference ROM.
MANUAL = {
    # llbit/llcvt runtime. The six functions appear in the same order and with
    # byte-identical size deltas in both ROMs:
    #   __ull_rshift +2C __ull_rem +3C __ull_div +3C __ll_lshift +2C __ll_rem +3C __ll_div
    0x80026E1C: "__ull_rem",
    0x80026EC0: "__ll_rem",

    # Si access queue: 0x80027E60 is called by osContInit, and 0x80027EB0 /
    # 0x80027EF4 are called by osPfsIsPlug. Both callers are confirmed matches.
    0x80027E60: "__osSiCreateAccessQueue",
    0x80027EB0: "__osSiGetAccess",
    0x80027EF4: "__osSiRelAccess",

    # Pi access queue: the same trio, by elimination once the Si trio is fixed
    # (the candidate set for each is exactly {Pi, Si}).
    0x8002ADD0: "__osPiCreateAccessQueue",
    0x8002AE20: "__osPiGetAccess",
    0x8002AE64: "__osPiRelAccess",

    # Same translation unit as osContInit / osPfsIsPlug respectively.
    0x80028090: "__osContGetInitData",
    0x8002AA40: "__osPfsGetInitData",

    # osViSwapBuffer (a confirmed match) writes through D_8004AED4, so that is
    # __osViNext and D_8004AED0 is __osViCurr. Each getter reads one of them.
    0x80028F20: "osViGetNextFramebuffer",
    0x80035050: "osViGetCurrentFramebuffer",

    # alMainBusParam sits 0x30 before alMainBusPull (a confirmed match), the
    # same adjacency the reference ROM has. alAuxBusParam is then the other.
    0x8002D000: "alMainBusParam",
    0x8002DDB0: "alAuxBusParam",

    # Immediately follows guFrustumF at +0x154, exactly as in the reference.
    0x80031F84: "guFrustum",

    # Two identical retail no-op varargs stubs 0x1C apart. The reference has the
    # same pair in the same order: osSyncPrintf then rmonPrintf.
    0x80030440: "osSyncPrintf",
    0x8003045C: "rmonPrintf",

    # One-line register reads, identical once the %hi/%lo is masked. The
    # register each one names it outright.
    0x80033C60: "osAiGetLength",     # AI_LEN_REG    0xA4500004
    0x800346A0: "__osSpGetStatus",   # SP_STATUS_REG 0xA4040010

    # Likewise, one-line global reads distinguished by the global. D_8004AED0 is
    # __osViCurr (osViGetCurrentFramebuffer reads it; osViSwapBuffer writes the
    # adjacent __osViNext), and D_80049944 is __osActiveQueue -- its only other
    # referencer is in the thread-scheduler TU that holds __osEnqueueThread.
    0x800349D0: "__osViGetCurrentContext",
    0x80034A70: "__osGetActiveQueue",
}


# ---------------------------------------------------------------- normalising

def _op(w):
    return w >> 26


def _rs(w):
    return (w >> 21) & 0x1F


def _rt(w):
    return (w >> 16) & 0x1F


# I-type opcodes whose 16-bit immediate can carry a %lo relocation.
LO_OPS = {
    0x08, 0x09,                                # addi addiu
    0x0D,                                      # ori
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,  # lb lh lwl lw lbu lhu lwr
    0x28, 0x29, 0x2A, 0x2B, 0x2E,              # sb sh swl sw swr
    0x31, 0x35, 0x39, 0x3D,                    # lwc1 ldc1 swc1 sdc1
    0x37, 0x3F,                                # ld sd
}


def normalize(words):
    """Mask the operands a relocation would change, keeping structure intact.

    j/jal targets are absolute and lui immediates are %hi halves, so both are
    masked; the register a lui writes is tracked so the paired %lo immediate is
    masked too. Branch displacements are PC-relative and therefore identical
    between the two links, so they are kept -- they carry most of the signal.
    """
    hi_regs = set()
    out = []
    for w in words:
        o = _op(w)
        if o in (0x02, 0x03):        # j, jal
            w &= 0xFC000000
        elif o == 0x0F:              # lui
            hi_regs.add(_rt(w))
            w &= 0xFFFF0000
        elif o in LO_OPS:
            if _rs(w) in hi_regs:    # the %lo half of a %hi/%lo pair
                w &= 0xFFFF0000
                hi_regs.discard(_rs(w))
            elif o in (0x08, 0x09, 0x0D):
                hi_regs.discard(_rt(w))  # overwritten with something else
        out.append(w)
    return b"".join(struct.pack(">I", w) for w in out)


def trim(words):
    """Drop inter-function alignment padding so both sides compare equal."""
    while words and words[-1] == 0:
        words.pop()
    return words


# ------------------------------------------------------------ reference decomp

def load_reference(ref):
    rom_path = ref / "config/usa/baserom.decompressed.z64"
    sym_path = ref / "config/usa/symbol_addrs/symbol_addrs.txt"
    if not rom_path.exists() or not sym_path.exists():
        sys.exit(
            f"reference decomp not usable at {ref}\n"
            f"  need {rom_path.relative_to(ref)} and {sym_path.relative_to(ref)}"
        )
    rom = rom_path.read_bytes()

    syms = []
    for line in sym_path.read_text().splitlines():
        m = re.match(r"\s*(\w+)\s*=\s*(0x[0-9A-Fa-f]+)\s*;(.*)", line)
        if m and "type:func" in m.group(3):
            syms.append((int(m.group(2), 16), m.group(1)))
    syms.sort()

    funcs = {}
    for i, (vram, name) in enumerate(syms):
        end = syms[i + 1][0] if i + 1 < len(syms) else vram + 0x400
        size = end - vram
        off = vram - DELTA
        if not (8 <= size <= 0x4000) or off < 0 or off + size > len(rom):
            continue
        words = list(struct.unpack(f">{size // 4}I", rom[off:off + size]))
        funcs[name] = trim(words)
    return funcs


# ---------------------------------------------------------------- this project

INSN = re.compile(r"/\*\s*([0-9A-F]+)\s+([0-9A-F]{8})\s+([0-9A-F]{8})\s*\*/")


def load_target(version):
    asm = REPO / "asm" / version
    if not asm.is_dir():
        sys.exit(f"no disassembly at {asm} -- run `make setup` first")

    funcs = {}
    for path in sorted(asm.glob("main*.s")):
        cur = None
        for line in path.read_text().splitlines():
            g = re.match(r"\s*glabel\s+(\w+)", line)
            if g:
                cur = g.group(1)
                funcs[cur] = {"words": [], "file": path.name, "vram": None}
                continue
            if re.match(r"\s*endlabel", line):
                cur = None
                continue
            if cur:
                m = INSN.search(line)
                if m:
                    # Take the address from the disassembly, not from the label.
                    # Once a function is named in symbol_addrs.txt its label is
                    # `osInitialize`, not `func_80028B10_29710`, and parsing the
                    # label would raise -- which is exactly what happened after
                    # Phase C named twelve functions.
                    if funcs[cur]["vram"] is None:
                        funcs[cur]["vram"] = int(m.group(2), 16)
                    funcs[cur]["words"].append(int(m.group(3), 16))
    for info in funcs.values():
        trim(info["words"])
    return {k: v for k, v in funcs.items() if v["words"]}


def vram_of(info):
    """First instruction's address, as disassembled."""
    return info["vram"]


# --------------------------------------------------------------------- driver

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ref", type=Path, default=DEFAULT_REF,
                    help="reference decomp with a baserom and named libultra symbols")
    ap.add_argument("--version", default="usa")
    ap.add_argument("--report", action="store_true", help="print only, do not write")
    ap.add_argument("--force", action="store_true",
                    help="overwrite even if names would be lost or duplicated")
    args = ap.parse_args()

    ref = load_reference(args.ref)
    target = load_target(args.version)

    index = defaultdict(set)
    for name, words in ref.items():
        index[normalize(words)].add(name)

    named, ambiguous, collisions = {}, {}, defaultdict(list)
    for label, info in target.items():
        vram = vram_of(info)
        if vram in MANUAL:
            named[vram] = (MANUAL[vram], label, info)
            collisions[MANUAL[vram]].append(vram)
            continue
        cands = index.get(normalize(info["words"]))
        if not cands:
            continue
        if len(cands) == 1:
            name = next(iter(cands))
            named[vram] = (name, label, info)
            collisions[name].append(vram)
        else:
            ambiguous[vram] = (sorted(cands), label, info)

    # A name may only be used once; anything still doubled is unresolved.
    dupes = {n: v for n, v in collisions.items() if len(v) > 1}
    for name, vrams in dupes.items():
        for v in vrams:
            named.pop(v, None)

    lib_total = sum(1 for i in target.values() if vram_of(i) >= LIBULTRA_VRAM_START)
    stray = [v for v in named if v < LIBULTRA_VRAM_START]

    print(f"reference functions:      {len(ref)}")
    print(f"target functions:         {len(target)}  "
          f"({lib_total} in the libultra region)")
    print(f"named:                    {len(named)}")
    print(f"  of which manual:        {sum(1 for v in named if v in MANUAL)}")
    print(f"ambiguous (left unnamed): {len(ambiguous)}")
    print(f"unresolved duplicates:    {len(dupes)}")
    print(f"still unnamed in region:  {lib_total - len(named)}")
    print(f"matches outside region:   {len(stray)}   <- expect 0")

    if ambiguous:
        print("\nambiguous:")
        for vram, (cands, label, _) in sorted(ambiguous.items()):
            print(f"  {vram:#010x}  {label:<28} {' | '.join(cands)}")
    if dupes:
        print("\nunresolved duplicates:")
        for name, vrams in sorted(dupes.items()):
            print(f"  {name:<28} {', '.join(f'{v:#x}' for v in vrams)}")
    if stray:
        print("\nWARNING: matched outside the libultra region (likely false positives):")
        for vram in sorted(stray):
            print(f"  {vram:#010x}  {named[vram][0]}")

    if args.report:
        return

    out = REPO / "config" / args.version / "symbol_addrs" / "libultra_syms.txt"

    # Refuse to clobber the committed file with a worse one.
    #
    # This tool reads asm/<version>/main*.s. Every libultra TU that has since
    # been decompiled to C is no longer there to fingerprint, so a plain rerun
    # silently drops names the committed file already has -- and adds names that
    # have since been asserted by hand in symbol_addrs.txt, which then defines
    # them twice. Following the README's old "regenerate and make setup" broke
    # the build both ways, and nothing said so.
    #
    # The generated file is still the right home for these; it just cannot be
    # rebuilt from asm alone any more. So compare first and make the damage the
    # user's explicit choice.
    lost, collide = [], []
    if out.exists():
        prev = set(re.findall(r"^(\w+)\s*=\s*0x", out.read_text(), re.M))
        lost = sorted(prev - {n for n, _, _ in named.values()})
    hand = out.parent / "symbol_addrs.txt"
    if hand.exists():
        hand_names = set(re.findall(r"^(\w+)\s*=\s*0x", hand.read_text(), re.M))
        collide = sorted(hand_names & {n for n, _, _ in named.values()})

    if (lost or collide) and not args.force:
        print()
        if lost:
            print(f"REFUSING TO WRITE: {len(lost)} name(s) in the committed file that "
                  f"this run cannot see.")
            print("  Their TUs are decompiled to C, so they are no longer in "
                  "asm/*/main*.s to fingerprint:")
            for n in lost:
                print(f"    {n}")
        if collide:
            print(f"REFUSING TO WRITE: {len(collide)} name(s) already asserted by hand "
                  f"in symbol_addrs.txt.")
            print("  Writing them here too would define each symbol twice:")
            for n in collide:
                print(f"    {n}")
        print("\nThe committed file is the better of the two and is left alone.")
        print("Use --force to overwrite anyway, or --report to just see the numbers.")
        raise SystemExit(1)

    lines = [
        "// libultra 2.0H symbols recovered by fingerprinting against the mnsg",
        "// decompilation. Generated by tools/fingerprint_libultra.py -- do not",
        "// hand-edit; put hand-derived symbols in symbol_addrs.txt instead.",
        "//",
        f"// {len(named)} functions, ROM 0x{LIBULTRA_ROM_START:X} onwards.",
        "",
    ]
    # No size: -- the word counts here have alignment padding trimmed off, so
    # they can understate a function and splat would split it in the wrong place.
    for vram, (name, _label, _info) in sorted(named.items()):
        lines.append(f"{name} = 0x{vram:08X}; // type:func rom:0x{vram - DELTA:X}")
    out.write_text("\n".join(lines) + "\n")
    print(f"\nwrote {out.relative_to(REPO)}  ({len(named)} symbols)")


if __name__ == "__main__":
    main()
