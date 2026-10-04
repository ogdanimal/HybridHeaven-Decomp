#!/usr/bin/env python3
"""
Proposes the text/data boundary for each RAM-loaded overlay.

Promoting an archive file to a `code` segment (gen_splat_yaml.py's
OVERLAY_FILES) needs the ROM offset where the overlay's code ends and its data
begins. Disassembling data as instructions is not a cosmetic problem: it
produces `pref`/`cache` opcodes that vr4300 `as` rejects, and -- worse -- data
that decodes cleanly but reassembles to different bytes.

The proposal is the end of the last function: the last `jr $ra` plus its delay
slot, rounded up to 16 because every segment boundary in this project has to be
16-byte aligned. That is a heuristic, not a proof. It is wrong whenever an
overlay puts data *between* functions rather than after them, so a proposal is
something to test with a build, not to trust.

    uv run python tools/overlay_bounds.py           # one row per overlay
    uv run python tools/overlay_bounds.py --dict    # paste-ready OVERLAY_FILES
"""

import argparse
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from gen_splat_yaml import read_file_table, read_load_table  # noqa: E402
from overlay_map import is_code  # noqa: E402

ROOT = Path(__file__).parent.parent

JR_RA = 0x03E00008


def propose(blob: bytes, start: int) -> tuple[int | None, int]:
    """Returns (text_end_rom, trailing_data_bytes); text_end is None if all code."""
    n = len(blob) // 4
    words = struct.unpack_from(f">{n}I", blob, 0)
    last = max(k for k, w in enumerate(words) if w == JR_RA)
    end_word = last + 2  # the delay slot belongs to the function
    text_end = start + end_word * 4
    text_end = (text_end + 15) & ~15  # every boundary must be 16-byte aligned
    if text_end >= start + len(blob):
        return None, 0
    return text_end, start + len(blob) - text_end


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", default="usa")
    ap.add_argument("--dict", action="store_true", help="print a paste-ready OVERLAY_FILES")
    args = ap.parse_args()

    rom = (ROOT / "config" / args.version / "baserom.decompressed.z64").read_bytes()
    table = read_file_table(rom)
    load = read_load_table(rom, len(table) - 1)

    rows = []
    for i in range(len(table) - 1):
        start, end = table[i], table[i + 1]
        if end == start or load[i][0] >> 24 != 0x80:
            continue
        blob = rom[start:end]
        if not is_code(blob):
            continue
        text_end, data_size = propose(blob, start)
        rows.append((i, start, end, load[i][0], text_end, data_size))

    if args.dict:
        print("OVERLAY_FILES: dict[int, int | None] = {")
        for i, _, _, _, text_end, _ in rows:
            print(f"    {i}: " + (f"0x{text_end:X}," if text_end else "None,"))
        print("}")
        return 0

    print(f"{len(rows)} RAM-loaded code overlays\n")
    print(f"  {'file':>5} {'rom':>9} {'vram':>10} {'size':>8} {'text_end':>9} "
          f"{'text':>8} {'data':>8}")
    all_code = 0
    for i, start, end, vram, text_end, data_size in rows:
        if text_end is None:
            all_code += 1
            print(f"  {i:>5} {start:>9X} {vram:>10X} {end - start:>8X} "
                  f"{'-':>9} {end - start:>8X} {'0':>8}")
        else:
            print(f"  {i:>5} {start:>9X} {vram:>10X} {end - start:>8X} "
                  f"{text_end:>9X} {text_end - start:>8X} {data_size:>8X}")
    print(f"\n  {all_code} are entirely code; {len(rows) - all_code} have a trailing "
          f"data region")
    return 0


if __name__ == "__main__":
    sys.exit(main())
