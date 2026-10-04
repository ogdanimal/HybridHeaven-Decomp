#!/usr/bin/env python3
"""
Generates config/<version>/splat.yaml for Hybrid Heaven.

Archive files listed in the Nisitenma-Ichigo table are emitted as plain `bin`
segments, except those named in OVERLAY_FILES, which become `code` segments with
a real vram taken from the load-address table (see the mnsg decomp for the
pattern). Promotion is per-file and deliberately incremental: each one changes
how splat emits that segment, so add a few, rebuild, and confirm both hashes
before adding more.
"""

import argparse
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).parent.parent

# --- Static segment layout, recovered from the entry stub and reference analysis ---
ENTRY_ROM = 0x1000
ENTRY_VRAM = 0x80000400
MAIN_ROM = 0x1060           # first function after the entry stub
MAIN_VRAM = 0x80000460
# VR4300 code actually ends at 0x35D24, where the first RSP ucode blob starts.
# We cut at 0x35D30 instead so both .text (0x34CD0) and .data (0x28AA0) are
# multiples of 16 -- GNU as pads each section up to its 16-byte section
# alignment, and any leftover shifts the entire image. The three ucode words
# that land in .text disassemble and reassemble identically.
TEXT_END_ROM = 0x35D30
BSS_ROM_END = 0x5E7D0       # .data end; == bss vram under the contiguous mapping
BSS_VRAM = 0x8005DBD0       # cleared by the entry stub
BSS_SIZE = 0x80DC0          # ditto
SIGNATURE = b"Nisitenma-Ichigo"

# Second table, immediately before the file-offset table: 624 entries of two
# big-endian u32 {load_start, load_end}. Entry i belongs to file i. See
# tools/overlay_map.py, which prints it and verifies it against the boot path.
ADDR_TABLE_ROM = 0x3885C

# Archive files promoted from `bin` to `code` segments, mapped to the ROM offset
# where the overlay's code ends and its data begins (None = all code). Only
# files the loader places at a RAM (0x8xxxxxxx) address and that contain MIPS
# code belong here -- `uv run python tools/overlay_map.py` lists them, 92 in all.
#
# The boundary is not optional. Disassembling an overlay's data as instructions
# is how you get `pref`/`cache` opcodes that vr4300 `as` rejects outright, and,
# worse, data that happens to decode cleanly and reassembles to different bytes.
# `tools/overlay_bounds.py` proposes a boundary from the last `jr $ra`.
#
# Promoting a file makes splat disassemble it and the build assemble and link
# it, so its bytes have to round-trip exactly. Add incrementally and re-run both
# `make` and `make COMPRESSED=yes` after each batch.
OVERLAY_FILES: dict[int, int | None] = {
    7: 0x532780,
    8: 0x5923F0,
    9: 0x5C7B70,
    10: 0x5ED0B0,
    11: 0x5F52C0,
    12: 0x5FD590,
    13: 0x609450,
    14: 0x61ED80,
    15: 0x62FDA0,
    16: 0x64D890,
    17: 0x65F8D0,
    18: 0x66F020,
    19: 0x6749A0,
    20: 0x67C490,
    21: 0x693CD0,
    23: 0x6AF200,
    24: 0x6CC170,
    25: 0x6E91F0,
    26: 0x6FC780,
    27: 0x71F800,
    28: 0x72B2C0,
    29: 0x733F10,
    30: 0x737E20,
    31: 0x73FC80,
    32: 0x751C80,
    33: 0x75B790,
    34: 0x762D60,
    35: 0x766B30,
    36: 0x76B270,
    37: 0x771110,
    38: 0x779D20,
    39: 0x780C40,
    40: 0x7880C0,
    41: 0x78B320,
    42: 0x793510,
    43: 0x79ECF0,
    44: 0x7A6770,
    45: 0x7AF580,
    46: 0x7B34E0,
    47: 0x7BB390,
    48: 0x7C0D90,
    49: 0x7C3A90,
    50: 0x7C9020,
    51: 0x7CCA90,
    52: 0x7D3880,
    53: 0x7DB720,
    54: 0x7DE2E0,
    55: 0x7FA9F0,
    56: 0x8290F0,
    57: 0x831450,
    58: 0x831E80,
    59: 0x832750,
    60: 0x833200,
    61: 0x833DA0,
    62: 0x834870,
    63: 0x835530,
    64: 0x835D20,
    65: 0x836910,
    66: 0x837680,
    67: 0x838410,
    68: 0x838F10,
    69: 0x839C60,
    70: 0x83A750,
    71: 0x83B250,
    72: 0x83BF50,
    73: 0x83CBD0,
    74: 0x83D690,
    75: 0x83E190,
    76: 0x83ECF0,
    77: 0x83F5C0,
    78: 0x840100,
    79: 0x8409B0,
    80: 0x841270,
    81: 0x841CB0,
    82: 0x842670,
    83: 0x843350,
    84: 0x843F50,
    85: 0x844C40,
    86: 0x845B30,
    87: 0x846590,
    88: 0x847390,
    89: 0x847DF0,
    90: 0x848980,
    91: 0x8493B0,
    92: 0x84A4E0,
    93: 0x84B690,
    94: 0x84C880,
    95: 0x84D510,
    96: 0x84DC50,
    97: 0x84E9A0,
    98: 0x84EF90,
    99: 0x8525D0,
}

# Overlays that get `bss_size` but no bss *subsegment*.
#
# splat keys symbols by vram, so two overlays that share a RAM slot and both
# claim an address produce one symbol emitted from two objects, and the link
# fails with a multiple definition. file_24's .bss covers 0x801E0D10, where
# file_8 has real .data, and both emit D_801E0D10_6D4280.
#
# Dropping the subsegment costs file_24 a sized .file_24_bss in the ELF (the
# section is emitted, but empty). That is the cheaper side of the trade: file_8's
# data is real bytes the recompiler needs, file_24's bss is zeroes. Revisit if
# the runtime turns out to need every overlay's bss extent.
NO_BSS_SUBSEGMENT: set[int] = {
    24,
}

# Translation units that have been decompiled to C. Maps the TU's ROM start to
# its path under src/ (no extension). Every key must also be a boundary in
# file_boundaries.txt, or the TU it names does not exist.
#
# Emitting a `c` subsegment makes splat write the linker script against
# build/<ver>/src/<path>.c.o instead of the asm object, so the stale
# asm/<ver>/main_<addr>.s is removed below to keep it out of the link.
C_FILES: dict[int, str] = {
    0x29610: "libultra/os/virtualtophysical",
    0x2A930: "libultra/gu/mtxutil",
    0x2BF80: "libultra/audio/synsetpan",
    0x2E9B0: "libultra/audio/auxbus",
    0x31080: "libultra/audio/filter",
    0x311D0: "libultra/audio/heapinit",
    0x315B0: "libultra/io/sp",
    0x35290: "libultra/io/spsetstat",
    0x352A0: "libultra/io/spgetstat",
    0x35610: "libultra/audio/heapalloc",
    0x35A40: "libultra/audio/synallocfx",
    0x35AE0: "libultra/audio/synstopvoice",
    0x35B60: "libultra/audio/syndelete",
}

HEADER = """\
name: Hybrid Heaven (USA)
sha1: {sha1}

options:
  basename: hybridheaven
  compiler: IDO
  platform: n64

  header_encoding: ASCII

  target_path: config/{ver}/baserom.decompressed.z64
  ld_script_path: .splat/{ver}/hybridheaven.ld
  elf_path: build/{ver}/hybridheaven.elf
  base_path: ../../

  undefined_funcs_auto_path: .splat/{ver}/undefined_funcs_auto.ld
  undefined_syms_auto_path: .splat/{ver}/undefined_syms_auto.ld

  symbol_addrs_path:
    - config/{ver}/symbol_addrs/symbol_addrs.txt
    - config/{ver}/symbol_addrs/libultra_syms.txt
  reloc_addrs_path:
    - config/{ver}/reloc_addrs/reloc_addrs.txt

  asm_path: asm/{ver}
  src_path: src
  build_path: build/{ver}
  asset_path: bin/{ver}

  symbol_name_format: $VRAM_$ROM

  find_file_boundaries: True
  migrate_rodata_to_functions: True
  rodata_string_guesser_level: 2
  gfx_ucode: f3dex

  # This game's sections are packed with only 4-byte alignment. splat's default
  # `. = ALIGN(., 16)` after every section/segment inserts padding that shifts
  # the whole image, so turn both off.
  ld_align_section_vram_end: False
  ld_align_segment_vram_end: False

segments:
  - name: header
    type: header
    start: 0x0

  - name: ipl3
    type: bin
    start: 0x40

  # subalign 4, not 16: the .text/ucode boundary at 0x{text_end:X} is only
  # 4-byte aligned in the original, so forcing 16 inserts padding and shifts
  # the whole image.
  - name: entry
    type: code
    start: 0x{entry_rom:X}
    vram: 0x{entry_vram:X}
    subalign: 4
    subsegments:
    - [0x{entry_rom:X}, hasm, entry]

  - name: main
    type: code
    start: 0x{main_rom:X}
    vram: 0x{main_vram:X}
    bss_size: 0x{bss_size:X}
    subalign: 4
    subsegments:
{text_subsegments}\
    # RSP microcode and .data/.rodata. Split these out into rodata/data/ucode
    # subsegments as they get identified.
    - [0x{text_end:X}, data, main_data]
    - {{ start: 0x{bss_rom:X}, type: bss, vram: 0x{bss_vram:X}, name: main }}
"""


def read_boundaries(path: Path) -> list[int]:
    """Reads TU boundaries (ROM offsets) from config, ignoring comments."""
    if not path.exists():
        return []
    out = []
    for line in path.read_text().splitlines():
        line = line.split("#")[0].strip()
        if line:
            out.append(int(line, 16))
    return sorted(set(out))


def read_load_table(rom: bytes, count: int) -> list[tuple[int, int]]:
    """Reads {load_start, load_end} from the load-address table at ADDR_TABLE_ROM."""
    return [struct.unpack_from(">II", rom, ADDR_TABLE_ROM + i * 8) for i in range(count)]


def read_file_table(rom: bytes) -> list[int]:
    sig = rom.find(SIGNATURE)
    if sig < 0:
        raise SystemExit("Nisitenma-Ichigo signature not found")
    off = sig + len(SIGNATURE)
    raw = []
    while True:
        (v,) = struct.unpack_from(">I", rom, off + len(raw) * 4)
        if v == 0:
            break
        raw.append(v & 0x7FFFFFFF)
    return raw


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", default="usa")
    args = ap.parse_args()
    ver = args.version

    rom_path = ROOT / "config" / ver / "baserom.decompressed.z64"
    rom = rom_path.read_bytes()
    sha1 = hashlib.sha1(rom).hexdigest()

    # One asm subsegment per translation unit. Boundaries must be 16-byte
    # aligned: GNU as pads each object's .text up to its section alignment, and
    # any leftover padding shifts every following byte in the ROM.
    bounds = read_boundaries(ROOT / "config" / ver / "file_boundaries.txt")
    misaligned = [b for b in bounds if b % 16]
    if misaligned:
        raise SystemExit(
            "file_boundaries.txt has non-16-aligned offsets: "
            + ", ".join(f"0x{b:X}" for b in misaligned)
        )
    bounds = [b for b in bounds if MAIN_ROM < b < TEXT_END_ROM]

    unknown = sorted(set(C_FILES) - set(bounds) - {MAIN_ROM})
    if unknown:
        raise SystemExit(
            "C_FILES names TU starts that are not in file_boundaries.txt: "
            + ", ".join(f"0x{b:X}" for b in unknown)
        )

    def subsegment(rom: int, asm_name: str) -> str:
        if rom in C_FILES:
            return f"    - [0x{rom:X}, c, {C_FILES[rom]}]\n"
        return f"    - [0x{rom:X}, asm, {asm_name}]\n"

    lines = [subsegment(MAIN_ROM, "main")]
    lines += [subsegment(b, f"main_{b:X}") for b in bounds]

    # splat only stops generating the .s for a TU once it is a `c` subsegment;
    # a leftover file from an earlier split would still be assembled and linked.
    for tu in C_FILES:
        stale = ROOT / "asm" / ver / ("main.s" if tu == MAIN_ROM else f"main_{tu:X}.s")
        if stale.exists():
            stale.unlink()
            print(f"  removed stale {stale.relative_to(ROOT)}")

    table = read_file_table(rom)
    out = [
        HEADER.format(
            sha1=sha1,
            ver=ver,
            text_subsegments="".join(lines),
            entry_rom=ENTRY_ROM,
            entry_vram=ENTRY_VRAM,
            main_rom=MAIN_ROM,
            main_vram=MAIN_VRAM,
            text_end=TEXT_END_ROM,
            bss_rom=BSS_ROM_END,
            bss_vram=BSS_VRAM,
            bss_size=BSS_SIZE,
        )
    ]

    # Uncompressed asset blob between the static segment and the first archive file.
    first_file = table[0]
    out.append(f"\n  - name: assets\n    type: bin\n    start: 0x{BSS_ROM_END:X}\n")

    # One segment per Nisitenma-Ichigo file. Zero-length entries are skipped;
    # splat derives each segment's end from the next segment's start.
    load = read_load_table(rom, len(table) - 1)
    emitted = 0
    promoted = []
    for i in range(len(table) - 1):
        start, end = table[i], table[i + 1]
        if end == start:
            continue  # empty file
        if i in OVERLAY_FILES:
            load_start, load_end = load[i]
            if load_start >> 24 != 0x80:
                raise SystemExit(
                    f"file_{i} is in OVERLAY_FILES but its load address 0x{load_start:08X} "
                    "is an F3DEX segment address, not RAM"
                )
            # The loader zero-fills from the end of the file data up to load_end,
            # so the excess over the file's size is the overlay's .bss.
            bss = load_end - load_start - (end - start)
            subsegments = f"    - [0x{start:X}, asm, file_{i}]\n"
            text_end = OVERLAY_FILES[i]
            if text_end is not None:
                if not start < text_end < end:
                    raise SystemExit(
                        f"file_{i}: text/data boundary 0x{text_end:X} is outside "
                        f"the file (0x{start:X}-0x{end:X})"
                    )
                if text_end % 16:
                    raise SystemExit(
                        f"file_{i}: text/data boundary 0x{text_end:X} is not 16-byte aligned"
                    )
                subsegments += f"    - [0x{text_end:X}, data, file_{i}_data]\n"
            if bss and i not in NO_BSS_SUBSEGMENT:
                # `bss_size` alone leaves splat emitting a zero-length
                # .file_<i>_bss; the subsegment is what gives it a real size.
                # It starts where the file's bytes end, in both ROM and vram.
                subsegments += (
                    f"    - {{ start: 0x{end:X}, type: bss, "
                    f"vram: 0x{load_start + (end - start):X}, name: file_{i} }}\n"
                )
            # Each overlay gets its own exclusive_ram_id, i.e. its own symbol
            # space. Giving the tenants of a slot a *shared* id -- the obvious
            # reading of "these never coexist" -- makes splat unify symbols by
            # vram across them, and they collide: file_8 has .data at 0x801E0D10
            # where file_24 has .bss, so both emit D_801E0D10_6D4280 and the link
            # fails with a multiple definition. References between overlays are
            # resolved absolutely instead, by config/<ver>/overlay_syms.ld.
            out.append(
                f"\n  - name: file_{i}\n"
                f"    type: code\n"
                f"    start: 0x{start:X}\n"
                f"    vram: 0x{load_start:X}\n"
                f"    bss_size: 0x{bss:X}\n"
                f"    subalign: 4\n"
                f"    overlay: yes\n"
                f"    exclusive_ram_id: file_{i}\n"
                f"    subsegments:\n"
                f"{subsegments}"
            )
            promoted.append(i)
        else:
            out.append(f"\n  - name: file_{i}\n    type: bin\n    start: 0x{start:X}\n")
        emitted += 1

    missing = set(OVERLAY_FILES) - set(promoted)
    if missing:
        raise SystemExit(f"OVERLAY_FILES names empty/unknown files: {sorted(missing)}")

    # Same hazard as C_FILES: splat stops writing bin/<ver>/file_<i>.bin once the
    # segment is `code`, but a leftover from an earlier run would still be built.
    for i in promoted:
        stale = ROOT / "bin" / ver / f"file_{i}.bin"
        if stale.exists():
            stale.unlink()
            print(f"  removed stale {stale.relative_to(ROOT)}")

    out.append(f"\n  - [0x{len(rom):X}]\n")

    dest = ROOT / "config" / ver / "splat.yaml"
    dest.write_text("".join(out))
    print(f"wrote {dest.relative_to(ROOT)}")
    print(f"  baserom sha1     : {sha1}")
    print(f"  table entries    : {len(table)}")
    print(f"  file segments    : {emitted} (non-empty), {len(promoted)} promoted to code")
    print(f"  asset blob       : 0x{BSS_ROM_END:X}-0x{first_file:X}")
    print(f"  .text            : 0x{MAIN_ROM:X}-0x{TEXT_END_ROM:X} in {len(bounds)+1} translation units")
    print(f"  .data/ucode      : 0x{TEXT_END_ROM:X}-0x{BSS_ROM_END:X}")
    print(f"  .bss             : 0x{BSS_VRAM:X} size 0x{BSS_SIZE:X}")


if __name__ == "__main__":
    main()
