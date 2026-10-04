#!/usr/bin/env python3
"""
Recovers where every Nisitenma-Ichigo file is loaded in RAM.

Hybrid Heaven has a second table immediately before the archive's file-offset
table: 624 entries of two big-endian u32, at ROM 0x3885C (vram 0x80037C5C),
ending exactly where the `Nisitenma-Ichigo` signature begins. Entry i belongs to
file i, and holds {load_start, load_end}.

The loader is func_8000469C_529C (vram 0x8000469C), called as
`load(file_index, dest)` with file_index in 1..624, so it indexes this table at
file_index - 1. It reads the entry only for its size, decompresses or DMAs the
file to `dest`, invalidates icache and dcache over the result, then zero-fills
from the end of the file data up to dest + (load_end - load_start). That tail is
the overlay's .bss, which is why load_end - load_start is usually larger than the
file itself.

`dest` is the caller's to choose, so the addresses in the table are only
advisory in principle. In practice they are exact: the boot path in
asm/usa/main_1C60.s loads five files at hardcoded addresses, and all five match
their table entry. --verify checks those five and fails if any drifts.

Files whose load_start is 0x8xxxxxxx go to RAM. The rest carry an F3DEX segment
address (0x03, 0x08, 0x0D, ...) and are assets addressed through the display
list rather than loaded at a fixed RAM address.

    uv run python tools/overlay_map.py            # summary + RAM slot map
    uv run python tools/overlay_map.py --verify   # check against the boot path
    uv run python tools/overlay_map.py --csv      # one row per file
"""

import argparse
import struct
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from gen_splat_yaml import ADDR_TABLE_ROM, read_file_table, read_load_table  # noqa: E402

ROOT = Path(__file__).parent.parent

ADDR_TABLE_VRAM = 0x80037C5C
LOADER_VRAM = 0x8000469C

# (file_index, dest) pairs the boot path passes as immediates -- see
# asm/usa/main_1C60.s around 0x1F1C. The recovered table must agree with these.
BOOT_LOADS = [
    (2, 0x800CE9C0),
    (4, 0x800F41C0),
    (5, 0x8038F800),
    (7, 0x800F51C0),
    (8, 0x80107830),
]

# func_8001F204_1FE04(0x801BF1A0, 0x8038F800 - 0x801BF1A0) right after the boot
# loads: the arena the dynamically loaded overlays are allocated out of.
ARENA = (0x801BF1A0, 0x8038F800)


def load_entries(rom: bytes) -> list[tuple[int, int]]:
    return read_load_table(rom, len(read_file_table(rom)) - 1)


JR_RA = 0x03E00008


def opens_with_prologue(blob: bytes) -> bool:
    """True if the file's first word is `addiu $sp, $sp, -N`."""
    if len(blob) < 4:
        return False
    w = struct.unpack_from(">I", blob, 0)[0]
    return (w >> 16) == 0x27BD and bool(w & 0x8000)


def is_code(blob: bytes) -> bool:
    """True if the file contains MIPS function returns.

    A single `jr $ra` is enough, and that is a far sharper test than it looks.
    Measured over all 547 non-empty files: every one of the 454
    segment-addressed asset files contains *exactly zero*, while every
    RAM-loaded file that opens with a prologue has at least 0.59 per KB. The
    only RAM-loaded file with none is file 22, a repeating 8-word record table.

    The obvious alternative -- decoding words with rabbitizer and requiring a
    high fraction to be valid instructions -- is strictly worse. 29 asset files
    decode above 90%, while real overlays that open with a large data region
    (files 54 and 98) fall to 0.47 and 0.67. That test would drop their
    functions from the symbol table, which is the one error here that is
    expensive to notice late.

    Testing the first word for a prologue, as this used to, found 77 of 92.
    """
    n = len(blob) // 4
    if n == 0:
        return False
    return JR_RA in struct.unpack_from(f">{n}I", blob, 0)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", default="usa")
    ap.add_argument("--verify", action="store_true", help="check against the boot path only")
    ap.add_argument("--csv", action="store_true", help="one row per file")
    args = ap.parse_args()

    rom = (ROOT / "config" / args.version / "baserom.decompressed.z64").read_bytes()
    table = read_file_table(rom)
    entries = load_entries(rom)

    if args.verify:
        bad = [
            (idx, dest, entries[idx - 1][0])
            for idx, dest in BOOT_LOADS
            if entries[idx - 1][0] != dest
        ]
        for idx, dest, got in bad:
            print(f"MISMATCH file {idx}: boot loads at 0x{dest:08X}, table says 0x{got:08X}")
        if bad:
            return 1
        print(f"OK  {len(BOOT_LOADS)} hardcoded boot loads all agree with the table at "
              f"0x{ADDR_TABLE_ROM:X}")
        return 0

    rows = []
    for i, (start, end) in enumerate(entries):
        span = table[i + 1] - table[i]
        if not span:
            continue  # empty table entry
        blob = rom[table[i]:table[i + 1]]
        rows.append((i, start, end, span, end - start - span,
                     is_code(blob), opens_with_prologue(blob)))

    if args.csv:
        print("file,load_start,load_end,file_size,bss_size,is_code,opens_with_prologue")
        for i, s, e, span, bss, code, pro in rows:
            print(f"{i},0x{s:08X},0x{e:08X},0x{span:X},0x{bss:X},{int(code)},{int(pro)}")
        return 0

    ram = [r for r in rows if r[1] >> 24 == 0x80]
    seg = defaultdict(int)
    for r in rows:
        if r[1] >> 24 != 0x80:
            seg[r[1] >> 24] += 1

    print(f"{len(rows)} non-empty files")
    print(f"  {len(ram)} load to RAM ({sum(1 for r in ram if r[5])} are code, "
          f"{sum(1 for r in ram if r[6])} of those opening with a prologue)")
    print(f"  {sum(seg.values())} carry an F3DEX segment address: "
          + ", ".join(f"0x{k:02X}={v}" for k, v in sorted(seg.items())))
    print(f"\narena for dynamically loaded overlays: 0x{ARENA[0]:08X}-0x{ARENA[1]:08X}"
          f" ({ARENA[1] - ARENA[0]:#x})")

    slots = defaultdict(list)
    for r in ram:
        slots[r[1]].append(r)
    print(f"\n{len(slots)} distinct RAM load addresses -- a shared address is one slot that "
          f"several files take turns in:\n")
    print(f"  {'load addr':<10} {'files':>5}  {'max end':<10} {'max bss':>8}  kind")
    for addr in sorted(slots):
        v = slots[addr]
        kind = "code" if any(r[5] for r in v) else "data"
        print(f"  {addr:08X}   {len(v):>5}  {max(r[2] for r in v):08X}   "
              f"{max(r[4] for r in v):>#8x}  {kind}"
              + (f"  file_{v[0][0]}" if len(v) == 1 else
                 f"  files {', '.join(str(r[0]) for r in v[:8])}"
                 + ("..." if len(v) > 8 else "")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
