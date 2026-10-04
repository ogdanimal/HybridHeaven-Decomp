#!/usr/bin/env python3
"""
Compares a built object's .text against the same span of the decompressed ROM.

asm-differ's -o mode needs a matching object in expected/, which a translation
unit that has just been converted from asm to C does not have. This compares the
object directly against the baserom instead, so a TU can be checked the moment
it compiles.

Words that the linker would have relocated (jal/j targets, and the immediate of
any lui/addiu/lw/sw that carries a %hi/%lo) are reported separately from real
mismatches, since they cannot agree before linking.

    uv run python tools/check_tu.py                 # every TU in C_FILES
    uv run python tools/check_tu.py libultra/gu/mtxutil
"""

import argparse
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from gen_splat_yaml import C_FILES, TEXT_END_ROM, read_boundaries  # noqa: E402

ROOT = Path(__file__).parent.parent

# Opcodes whose immediate the linker rewrites, so a pre-link mismatch there is
# expected rather than a decompilation error.
RELOCATABLE = {0x02, 0x03}  # j, jal


def relocatable(word: int) -> bool:
    op = word >> 26
    if op in RELOCATABLE:
        return True
    # lui/addiu/lw/sw of a %hi/%lo pair: the immediate is a link-time address.
    return op in (0x0F, 0x09, 0x23, 0x2B)


def tu_end(start: int, bounds: list[int]) -> int:
    later = [b for b in bounds if b > start]
    return min(later) if later else TEXT_END_ROM


def obj_text(path: Path) -> bytes:
    out = subprocess.run(
        ["mips-linux-gnu-objcopy", "-O", "binary", "--only-section=.text", str(path), "/dev/stdout"],
        capture_output=True,
        check=True,
    )
    return out.stdout


def other_sections(path: Path) -> list[str]:
    """Non-empty .rodata/.data/.bss, which have nowhere to go until Phase 1.

    The linker script has a slot for each, but the bytes they would occupy are
    still inside the single undifferentiated `main_data` subsegment, so emitting
    any shifts the whole image.
    """
    out = subprocess.run(
        ["mips-linux-gnu-objdump", "-h", str(path)], capture_output=True, check=True, text=True
    ).stdout
    found = []
    for line in out.splitlines():
        f = line.split()
        if len(f) >= 3 and f[1] in (".rodata", ".data", ".bss") and int(f[2], 16):
            found.append(f"{f[1]} 0x{int(f[2], 16):X}")
    return found


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="*", help="src paths to check (default: all of C_FILES)")
    ap.add_argument("--version", default="usa")
    args = ap.parse_args()

    rom = (ROOT / "config" / args.version / "baserom.decompressed.z64").read_bytes()
    bounds = read_boundaries(ROOT / "config" / args.version / "file_boundaries.txt")

    selected = {s: p for s, p in C_FILES.items() if not args.paths or p in args.paths}
    if not selected:
        print(f"no TU matches {args.paths}", file=sys.stderr)
        return 2

    failed = 0
    for start in sorted(selected):
        path = selected[start]
        end = tu_end(start, bounds)
        want = rom[start:end]
        obj = ROOT / "build" / args.version / "src" / f"{path}.c.o"
        if not obj.exists():
            print(f"MISSING {path}: {obj} not built")
            failed += 1
            continue
        got = obj_text(obj)

        extra = other_sections(obj)
        if extra:
            print(f"SECTION {path}: emits {', '.join(extra)} -- no home until Phase 1 splits main_data")
            failed += 1
            continue

        if len(got) != len(want):
            print(f"SIZE    {path}: .text 0x{len(got):X}, TU 0x{start:X}-0x{end:X} is 0x{len(want):X}")
            failed += 1
            continue

        bad, reloc = [], 0
        for i in range(0, len(want), 4):
            w = int.from_bytes(want[i : i + 4], "big")
            g = int.from_bytes(got[i : i + 4], "big")
            if w == g:
                continue
            if relocatable(w) and relocatable(g) and (w >> 26) == (g >> 26):
                reloc += 1
            else:
                bad.append((start + i, w, g))

        note = f" ({reloc} relocated)" if reloc else ""
        if bad:
            failed += 1
            print(f"DIFF    {path}: {len(bad)}/{len(want)//4} words differ{note}")
            for rom_off, w, g in bad[:8]:
                print(f"            0x{rom_off:X}: rom {w:08X}  built {g:08X}")
            if len(bad) > 8:
                print(f"            ... {len(bad) - 8} more")
        else:
            print(f"OK      {path}: 0x{len(want):X} bytes{note}")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
