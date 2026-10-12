# hybridheaven

A decompilation of **Hybrid Heaven** (Konami, 1999) for the Nintendo 64.

It exists to serve a **native port to Windows, Linux and Android** by static
recompilation with [N64Recomp](https://github.com/N64Recomp/N64Recomp). This repo
produces the recompiler's input: an ELF describing the ROM's sections and
symbols. The build reproduces the retail ROM **byte-for-byte**, with the static
`.text` segment split into 137 translation units and all 92 RAM-loaded overlays
promoted to `code` segments at their real load addresses — 15,895 `FUNC` symbols
across 94 executable sections.

| | |
|---|---|
| Version | `usa` — Hybrid Heaven (USA), `NHVE` |
| Retail ROM sha1 | `16dbc21620b52deab5c5abf8a309ac60adfbee85` |
| Decompressed sha1 | `61ed3d5d5390c3c17b4026797b93be50a61dd6f2` |
| Compiler | IDO 5.3, `-O2 -mips2` (verified against retail code) |
| Microcode | F3DEX 2.06 / libultra 2.0H |

**Decompiling to C is not the road to the port.** The recompiler runs on the ELF,
not on C, and the runtime replaces libultra outright. What the port needed from
this repo was an ELF that matches the ROM and a symbol table — no C, and not one
changed byte. C earns its keep later, per-function, for writing patches. 198
libultra functions are identified by name (159 by fingerprinting, 39 by hand) and
13 translation units are decompiled to matching C in `src/libultra/`.

The port this feeds is
[HybridHeaven-Recomp](https://github.com/ogdanimal/HybridHeaven-Recomp).

## Building

```bash
# Debian/Ubuntu
sudo apt install build-essential git curl binutils-mips-linux-gnu
# uv manages Python and all Python dependencies
curl -LsSf https://astral.sh/uv/install.sh | sh
```

```bash
git clone --recursive https://github.com/ogdanimal/HybridHeaven-Decomp && cd HybridHeaven-Decomp
cp "/path/to/Hybrid Heaven (USA).z64" config/usa/baserom.z64
make setup            # decompress the archive, then split with splat
make                  # build; verifies against the decompressed sha1
make COMPRESSED=yes   # rebuild and re-compress; verifies against the retail sha1
```

`make setup` also downloads IDO 5.3 into `tools/ido-5.3/` — decompals'
[static recompilation](https://github.com/decompals/ido-static-recomp), pinned to
`v1.2` and checked against its sha256.

`make expected` snapshots a known-good build into `expected/` for `asm-differ`.

## How the ROM is laid out

Hybrid Heaven stores most of its content in Konami's **Nisitenma-Ichigo**
archive — the same format Mystical Ninja Starring Goemon uses, so the
[mnsg decomp](https://github.com/klorfmorf/mnsg)'s `rommy.py` works on it
unmodified. The archive is LZKN64-compressed and round-trips byte-exactly, so
the workflow is: decompress → split → rebuild → re-compress.

The file table is found by searching for the ASCII signature `Nisitenma-Ichigo`
(at `0x39BE0` here). Each following big-endian `u32` is one entry: bit 31 marks
compression, bits 0–30 are the ROM offset. A file ends where the next begins.
624 entries; 482 compressed, 65 stored, 77 empty.

### Static segment

Recovered from the entry stub at `0x80000400`, which clears bss and jumps to
`0x80001078`:

| Region | ROM | VRAM |
|---|---|---|
| header | `0x0` | — |
| ipl3 | `0x40` | — |
| entry | `0x1000` | `0x80000400` |
| `.text` (137 TUs) | `0x1060`–`0x35D30` | `0x80000460`– |
| `.data` + RSP ucode | `0x35D30`–`0x5E7D0` | |
| `.bss` (`0x80DC0`) | — | `0x8005DBD0` |
| uncompressed assets | `0x5E7D0`–`0x4E5F40` | |
| archive files | `0x4E5F40`– | |

Stack top is `0x80057BD0`. For the data segment `vram = rom + 0x7FFFF400`.

Everything from `0x35D30` to `0x5E7D0` is currently one undifferentiated `data`
subsegment. Splitting it into real `rodata`/`data`/ucode subsegments is the next
structural task; splat reports a jumptable at vram `0x8004B9D0`, so `.rodata`
likely starts at or before ROM `0x4C5D0`.

### RSP microcode

Embedded in `.data` and currently sitting there as raw `.word` data. There are
two SP tasks — gfx (F3DEX 2.06, `M_GFXTASK`) and audio (`aspMain`, `M_AUDTASK`) —
sharing one rspboot:

| region | ROM | VRAM | size |
|---|---|---|---|
| rspboot | `0x35CD0` | `0x800350D0` | `0xD0` |
| F3DEX text | `0x35DA0` | `0x800351A0` | `0x1000` |
| aspMain text | `0x37130` | `0x80036530` | `0xE20` |
| F3DEX data | `0x4E0F0` | `0x8004D4F0` | `0x800` |
| aspMain data | `0x4E510` | `0x8004D910` | `0x800` |

`aspMain` is byte-identical to Mystical Ninja's, and is the only microcode the
port has to recompile — RT64 implements F3DEX itself.

rspboot begins at `0x35CD0`, so the `.text` cut at `0x35D30` trails `0x60` bytes
of it into `.text`. That reassembles identically, so it is a segmentation
cosmetic rather than a build problem.

### Alignment — read this before editing `splat.yaml`

`splat.yaml` is **generated** by `tools/gen_splat_yaml.py`; edit that, not the
YAML. The generator encodes two hard-won constraints:

1. `ld_align_section_vram_end` and `ld_align_segment_vram_end` are both `False`,
   and segments use `subalign: 4`. splat's default `. = ALIGN(., 16)` after
   every section inserts padding this game doesn't have.
2. **Every translation-unit boundary must be 16-byte aligned.** GNU `as` pads
   each object's `.text` up to its 16-byte section alignment, and any leftover
   padding shifts every subsequent byte in the ROM. This is why `.text` is cut
   at `0x35D30` rather than `0x35D24` where VR4300 code actually ends — the
   three RSP ucode words that land in `.text` reassemble identically.
   `config/usa/file_boundaries.txt` is validated against this on every run.

## Overlays

The 547 archive files are loaded by `func_8000469C_529C` (vram `0x8000469C`),
called as `load(file_index, dest)`. A second table at ROM `0x3885C` (vram
`0x80037C5C`) holds `{load_start, load_end}` per file — 624 entries of two
big-endian `u32`, ending exactly where the `Nisitenma-Ichigo` signature begins.
The amount by which an entry exceeds its file's size is the `.bss` the loader
zero-fills.

```bash
uv run python tools/overlay_map.py           # RAM slot map
uv run python tools/overlay_map.py --verify  # check against the boot path
uv run python tools/overlay_bounds.py        # proposed text/data boundaries
```

93 files load to RAM across 11 distinct addresses (a shared address is one slot
several files take turns in); the other 454 carry an F3DEX segment address and
are reached through the display list. 92 of the 93 are code — the test is
whether the file contains a `jr $ra`, which separates the populations cleanly
(no asset file has one; no code file lacks one).

All 92 are promoted to `code` segments by `OVERLAY_FILES` in
`gen_splat_yaml.py`, which maps each to the ROM offset where its code ends and
its data begins. Four things this needs, each of which will bite if changed:

- **A text/data boundary per overlay.** Every overlay ends in data, and
  disassembling it as code yields `pref`/`cache` opcodes `as` rejects.
  `overlay_bounds.py` proposes one from the last `jr $ra`.
- **An explicit `bss` subsegment.** `bss_size:` alone yields a zero-length
  `.file_<i>_bss`.
- **One `exclusive_ram_id` per file**, not per RAM slot. A shared id makes splat
  unify symbols by vram across the slot's tenants, and they collide.
- **`config/usa/overlay_syms.ld`**, generated by `tools/gen_overlay_syms.py`:
  absolute addresses for the 37 references that cross between overlays. Such a
  reference names an address in a slot, not a symbol in a file, so it cannot be
  resolved at link time. Regenerate by running the tool until it reports 0 new.

### An overlay's vram does not identify a function

2139 vram addresses have a function defined by more than one section, because
the shared slots overlap. A consumer that binds a call to one arbitrary tenant of
such an address gets a wrong function — this is what the port used to crash on.
It is the same ambiguity `overlay_syms.ld` handles for data references, one level
up and applied to `jal`.

**It is not a decomp bug, and asserting a name in `symbol_addrs.txt` cannot fix
it**: the address does not identify a function until runtime. This is why
`undefined_funcs_report.py` refuses to guess for targets in shared slots.

### The two file numberings

Both conventions appear in this repo. The loader's `file_id` is **1-based** and
reads archive entry `file_id - 1`, while splat names its segments by the
**0-based** entry index. `.file_7` is the loader's file 8. `tools/overlay_map.py`
prints splat's numbering.

### Checking the absolute jal targets

```bash
uv run python tools/undefined_funcs_report.py         # the crossings
uv run python tools/undefined_funcs_report.py --all   # every entry
```

splat emits a `jal` target it cannot attribute to a segment into
`.splat/usa/undefined_funcs_auto.ld`, which links but erases the section
information N64Recomp needs to resolve a call from one relocatable section into
another. Most of the 173 entries there are harmless: an overlay reaching an
address inside its own section takes N64Recomp's in-section path and never needs
that information. Only an entry whose *caller* lives outside every section
containing the target can break recompilation, and the report is what tells the
two apart.

The baseline is **2 crossings, both known** — `0x8400103C` and `0x84001064`, RSP
branch displacements inside rspboot rather than VR4300 code, which the report
recognises and annotates. A run that ends in `Every crossing is a known one` is
clean; any third crossing is the thing to chase. The report also flags targets in
shared RAM slots, where several tenants define a function at the same vram and
asserting one tenant's name would be a guess rather than a fact.

## libultra

`.text` from ROM `0x26F00` to `0x35D30` is linked libultra 2.0H — 111 of the 137
translation units, but only 28% of the bytes, because they are small
one-function-per-file units.

Names matter here beyond documentation: N64Recomp recognises libultra by name
against its own `symbol_lists.cpp`, so a function still under a `func_XXXXXXXX`
placeholder is recompiled as game code and executed — running the game's own SI,
VI and PI drivers against registers the runtime does not emulate. Naming is
usually the whole fix; none of the functions named for this reason needed
decompiling.

The test for which unnamed functions matter is **not** "does it touch hardware
registers". `osEPiStartDma` and `osSetEventMesg` touch none and were both fatal —
one hung the boot thread forever, the other segfaulted inside ultramodern —
because they manipulate state the native runtime also owns. Run
`HybridHeaven-Recomp/tools/recomp_symbol_gap.py` for the current symbol-level
check.

mnsg cannot supply these by fingerprinting alone: it has no `osStopThread` at
all, and its `osInitialize`, `osCreateViManager` and `osPfsInitPak` differ in
size from Hybrid Heaven's, so the two games do not link an identical libultra
throughout.

### Fingerprinting

`tools/fingerprint_libultra.py` recovers names by fingerprinting against the
[mnsg](https://github.com/klorfmorf/mnsg) decomp: both games are IDO-built and
link the same libultra, so the library's object code is identical apart from
operands the linker relocated. Masking `jal`/`j` targets and `%hi`/`%lo` pairs
leaves an exact identifier, while PC-relative branch displacements — which carry
most of the signal — are kept.

Output goes to `config/usa/symbol_addrs/libultra_syms.txt`, which is generated
and committed; put hand-derived symbols in `symbol_addrs.txt` instead.

**The committed file can no longer be reproduced by rerunning the tool, and a
plain rerun is a regression.** It reads `asm/usa/main*.s`, so every libultra TU
that has since been decompiled to C is no longer there to fingerprint. A rerun
today yields 147 names against the committed 159: it drops 17 whose TUs moved to
C (`alHeapInit`, `guMtxIdent`, `osVirtualToPhysical`, the `__osSp*` trio and the
rest of the audio library) and adds 5 — `__osCleanupThread`,
`__osDispatchThread`, `__osExceptionPreamble`, `handle_CpU`, `send_mesg` — that
are now asserted by hand in `symbol_addrs.txt`, which would define each of them
twice.

The tool compares before writing and refuses rather than clobbering, so it is
safe to run:

```bash
uv run python tools/fingerprint_libultra.py --report   # numbers only, never writes
uv run python tools/fingerprint_libultra.py            # refuses, and says what it would lose
```

Regenerating for real means either extending the tool to read the decompiled C
TUs as well, or merging its output into the committed file by hand. `--force`
overwrites and is the wrong answer unless you have done one of those first.

### The decompiled translation units

13 translation units are matching C under `src/libultra/`, worked up from
[Quest64-Decomp](https://github.com/Ferrick90/Quest64-Decomp)'s `src/libultra/`
tree. Two facts govern the rest of that work:

- **The library was built per directory at different `-O` levels** — `-O1` for
  `os` and `io`, `-O2` for `gu`, `-O3` for `audio`. The Makefile carries a
  pattern rule per directory, each with the function that pinned it.
- **At `-O3`, IDO emits functions in reverse source order.** An `audio` file
  whose functions appear in the ROM as A, B has to be written B, A. At `-O1` and
  `-O2` the order is the source order.

A translation unit becomes C by adding its ROM start to `C_FILES` in
`tools/gen_splat_yaml.py`; that switches the subsegment from `asm` to `c` and
removes the stale `asm/usa/main_<addr>.s`. No padding work is needed — IDO pads
each object's `.text` to 16 bytes just as GNU `as` does, so the trailing `nop`s
a TU has in the ROM come back on their own.

## Decompiling

Boundaries in `config/usa/file_boundaries.txt` come from splat's
`find_file_boundaries`, which is a heuristic — it puts the boundary at the end of
a run of padding `nop`s, so a TU can come out larger than the object really was.
`check_tu.py` reports that as a size mismatch; the fix is an extra boundary (see
`0x352B0`).

To start on a translation unit, move its functions from `asm/usa/main_*.s` into a
`src/*.c` file, add it to `C_FILES`, and iterate with:

```bash
make expected                                  # once, from a matching build
uv run python tools/check_tu.py <src/path>     # object .text vs the baserom
uv run tools/asm-differ/diff.py -o <function>  # once the TU is already C
```

`check_tu.py` is the one to use while converting: `asm-differ -o` compares
against an object in `expected/`, and a TU that has just moved from asm to C has
none at its new path.

`tools/m2c/m2c.py` gives a first-pass C translation; `tools/context.py` builds a
context file for m2c and decomp.me.

### Feeding a function to decomp-permuter

`import.py` wants a `.s` holding one function, and the asm splat writes needs two
edits before it will take it:

```bash
sed -n '/^glabel <func>$/,/^endlabel <func>$/p' asm/usa/main_<addr>.s > /tmp/<func>.s
# prepend: .set noat / .set noreorder / .set gp=64 / .text
uv run tools/decomp-permuter/import.py src/<file>.c /tmp/<func>.s
```

- Use a bare `.text`, not splat's `.section .text, "ax"`. `import.py` splits the
  directive on whitespace and compares the second field against `".text"`, so the
  trailing comma makes it never find the function.
- Drop `.include "macro.inc"`. The permuter's own `prelude.inc` already defines
  `glabel`/`endlabel`, and `as` errors on the redefinition.
- Set the `-O` in `permuter_settings.toml` to the directory's level first — it is
  a single global setting and defaults to the game-code `-O2`.

## Layout

```
config/usa/     splat.yaml (generated), file_boundaries.txt, sha1s, rommy
                manifest, overlay_syms.ld (generated),
                symbol_addrs/ (libultra_syms.txt is generated)
tools/          rommy.py (archive codec), ido-5.3 (fetched), asm-processor, asm-differ,
                decomp-permuter, m2c, gen_splat_yaml.py,
                fingerprint_libultra.py, check_tu.py, overlay_map.py,
                overlay_bounds.py, gen_overlay_syms.py,
                undefined_funcs_report.py
libultra/       libultra 2.0H headers
asm/ bin/       splat output (generated, gitignored)
src/libultra/   decompiled C, plus the library's private headers
```

`tools/lzkn64_ref.py` is a dependency-free reference implementation of the
LZKN64 decompressor and file-table parser, useful for one-off ROM inspection.

## The three repos

Laid out the way Goemon 64: Recompiled is, since that is the stack this is
heading for:

| repo | role |
|---|---|
| **`HybridHeaven-Decomp`** (this one) | the decomp — matching build, segmentation, symbols. Becomes `lib/hybridheaven` inside the recomp, which uses it for headers when building patches. |
| `HybridHeaven-RecompSyms` | the generated `.syms.toml` / `.datasyms.toml`. Kept separate so mods can reference just the symbols, and to keep the megabyte-scale files out of the port's history. |
| `HybridHeaven-Recomp` | the port itself — recompiler config, patches, runtime, RT64. |

`HybridHeaven-RecompSyms` came first, because symbol dumping needs the overlay
list; `HybridHeaven-Recomp` followed, and carries `hybridheaven.toml`,
`aspMain.toml`, the overlay list and the dump config.

## Credits

Tooling and ROM-format work derive from the
[mnsg](https://github.com/klorfmorf/mnsg) decompilation of Mystical Ninja
Starring Goemon.

## License

The work in this repository — the decompiled source, configuration, tooling and
documentation — is dedicated to the public domain under
[CC0 1.0](LICENSE).

That covers only what was written for this project. The libultra SDK headers
under `libultra/` are Nintendo's and are not covered, nor is the game itself: no
game data is included, and building requires your own copy. The submodules under
`tools/` keep their own licenses.
