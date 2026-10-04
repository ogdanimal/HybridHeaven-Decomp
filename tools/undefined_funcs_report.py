#!/usr/bin/env python3
"""
Reports which of splat's absolute jal targets are called across a section
boundary, and therefore block static recompilation.

When splat cannot attribute a jal target to a segment it emits the address into
`.splat/<ver>/undefined_funcs_auto.ld` as an absolute symbol:

    func_80126744 = 0x80126744;

That links -- the address is right -- but an absolute symbol has no section, and
the `R_MIPS_26` the assembler produces against it carries none either. N64Recomp
needs the section: a call from one relocatable section into another is resolved
by runtime lookup, and without a section it cannot tell which. It fails with

    No function found for jal target: 0x80133AA0

Most entries in the file are harmless. An overlay reaching an address inside its
own section takes N64Recomp's in-section path and never needs the reloc. Only a
call whose *caller* lives outside every section containing the target crosses a
boundary, and only those have to be fixed -- by asserting the target's real name
in config/<ver>/symbol_addrs/symbol_addrs.txt so splat emits a section-bearing
symbol instead.

So this answers two questions the fix depends on: which entries cross, and
whether the target address names exactly one function. A shared RAM slot has
several tenants, and an address inside one is genuinely ambiguous -- which
overlay is resident there is a runtime question, and asserting one tenant's name
would be a guess. None of Hybrid Heaven's crossings is ambiguous today; all
eight land in .file_7, the sole tenant of its slot.

Needs a completed build, since it reads the ELF's section layout and symbols.

    uv run python tools/undefined_funcs_report.py            # the crossings
    uv run python tools/undefined_funcs_report.py --all      # every entry
"""

import argparse
import collections
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent

OBJDUMP_PREFIX = "mips-linux-gnu-"

# splat's generated name for an unattributed jal target is `func_<vram>`.
UNDEFINED_RE = re.compile(r"^(func_[0-9A-F]{8}) = 0x([0-9A-Fa-f]{8});")


def read_undefined(version: str) -> dict[str, int]:
    path = ROOT / ".splat" / version / "undefined_funcs_auto.ld"
    if not path.exists():
        sys.exit(f"{path} not found -- run `make setup` first")
    out = {}
    for line in path.read_text().splitlines():
        m = UNDEFINED_RE.match(line.strip())
        if m:
            out[m.group(1)] = int(m.group(2), 16)
    return out


def readelf(elf: Path, flag: str) -> str:
    return subprocess.run(
        [OBJDUMP_PREFIX + "readelf", flag, str(elf)],
        capture_output=True, text=True, check=True,
    ).stdout


def executable_sections(elf: Path) -> list[tuple[str, int, int]]:
    """Returns (name, vram, size) for every non-empty executable PROGBITS section."""
    pat = re.compile(
        r"^\s*\[\s*\d+\]\s+(\S+)\s+(\S+)\s+([0-9a-f]+)\s+[0-9a-f]+\s+([0-9a-f]+)"
        r"\s+\S+\s+(\S+)", re.M)
    rows = []
    for m in pat.finditer(readelf(elf, "-SW")):
        name, typ, addr, size, flags = m.groups()
        if typ == "PROGBITS" and "X" in flags and int(size, 16):
            rows.append((name, int(addr, 16), int(size, 16)))
    return rows


def function_symbols(elf: Path) -> dict[int, list[tuple[str, int]]]:
    """Maps vram -> [(name, section index)] for every FUNC symbol."""
    by_addr = collections.defaultdict(list)
    for line in readelf(elf, "-sW").splitlines():
        parts = line.split()
        if len(parts) < 8 or not parts[0].endswith(":") or parts[3] != "FUNC":
            continue
        if not parts[6].isdigit():
            continue
        by_addr[int(parts[1], 16)].append((parts[7], int(parts[6])))
    return by_addr


def referencing_files(names: list[str]) -> dict[str, set[str]]:
    """Which asm file mentions each undefined name. splat writes one per section."""
    refs = collections.defaultdict(set)
    patterns = {n: re.compile(r"\b" + n + r"\b") for n in names}
    for path in sorted((ROOT / "asm" / "usa").glob("*.s")):
        text = path.read_text()
        for name, pat in patterns.items():
            if pat.search(text):
                refs[name].add(path.stem)
    return refs


def section_of_asm(stem: str) -> str:
    """asm/usa/file_7.s is section .file_7; every other .s is part of .main."""
    return f".{stem}" if stem.startswith("file_") else ".main"


# Crossings that are understood and are not going to be fixed, so the report can
# exit 0 on a clean tree and a NEW crossing actually means something.
#
# Both of these are RSP branch displacements sitting inside the two rspboot
# pseudo-functions the recompiler ignores. They are not VR4300 code and there is
# no section for them to be in -- see PLAN.md on the undefined-funcs class.
ACCEPTED = {
    0x8400103C: "RSP branch displacement in rspboot, not VR4300 code",
    0x84001064: "RSP branch displacement in rspboot, not VR4300 code",
}


def makefile_basename() -> str:
    """Read BASENAME out of the Makefile, which is what names the built ELF."""
    m = re.search(r"^BASENAME\s*[:?]?=\s*(\S+)", (ROOT / "Makefile").read_text(), re.M)
    if not m:
        sys.exit("could not read BASENAME from the Makefile")
    return m.group(1)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", default="usa")
    ap.add_argument("--all", action="store_true",
                    help="list every entry, not just the crossings")
    args = ap.parse_args()

    # BASENAME comes from the Makefile, not from the directory name. They happen
    # to match in a default checkout, so deriving it from ROOT.name worked right
    # up until someone cloned into a differently named directory -- at which
    # point this looked for an ELF that is never built while the real one sat
    # next to it under its real name.
    elf = ROOT / "build" / args.version / f"{makefile_basename()}.elf"
    if not elf.exists():
        sys.exit(f"{elf} not found -- run `make` first")

    undefined = read_undefined(args.version)
    sections = executable_sections(elf)
    by_addr = function_symbols(elf)
    refs = referencing_files(list(undefined))

    crossings = []
    rows = []
    for name, addr in sorted(undefined.items(), key=lambda kv: kv[1]):
        holders = [s for s, vram, size in sections if vram <= addr < vram + size]
        callers = sorted({section_of_asm(s) for s in refs[name]})
        outside = [c for c in callers if c not in holders]
        targets = [n for n, _ in by_addr.get(addr, [])]
        rows.append((addr, holders, callers, outside, targets))
        if outside:
            crossings.append((addr, holders, outside, targets))

    if args.all:
        for addr, holders, callers, outside, targets in rows:
            mark = "CROSSES" if outside else "       "
            print(f"  {mark} {addr:08X}  in={','.join(holders) or '-':<12} "
                  f"called_from={','.join(callers) or '-':<24} "
                  f"targets={len(targets)}")
        print()

    print(f"{len(undefined)} absolute jal targets; {len(crossings)} called across a "
          f"section boundary\n")
    unexpected = 0
    for addr, holders, outside, targets in crossings:
        if not holders:
            note = "target is in NO section -- not VR4300 code"
        elif len(targets) == 1:
            note = f"assert {targets[0]}"
        elif not targets:
            note = "no FUNC symbol at this address -- needs a forced one"
        else:
            note = f"AMBIGUOUS -- {len(targets)} tenants: {', '.join(targets)}"
        if addr in ACCEPTED:
            note = f"expected -- {ACCEPTED[addr]}"
        else:
            unexpected += 1
        print(f"  {'   ' if addr in ACCEPTED else 'NEW'} {addr:08X}  "
              f"in={','.join(holders) or '-':<10} "
              f"called_from={','.join(outside):<10}  {note}")

    missing = sorted(set(ACCEPTED) - {c[0] for c in crossings})
    for addr in missing:
        print(f"  GONE {addr:08X}  no longer crosses -- drop it from ACCEPTED")

    if unexpected or missing:
        print(f"\n{unexpected} unexpected crossing(s), {len(missing)} stale "
              f"exception(s).")
        return 1

    print("\nEvery crossing is a known one.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
