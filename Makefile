find-command = $(shell which $(1) 2>/dev/null)

BASENAME    = hybridheaven
VERSION    ?= usa
COMPRESSED  = no

##### Directories #####
BUILD_DIR = build/$(VERSION)
CONFIG_DIR = config/$(VERSION)

BIN_DIRS := $(shell find bin/$(VERSION) -type d 2>/dev/null)
ASM_DIRS := $(shell find asm -type d -not -path "asm/$(VERSION)/nonmatchings*" 2>/dev/null)
SRC_DIRS := $(shell find src -type d 2>/dev/null)

##### Tools #####
ifneq      ($(call find-command,mips-linux-gnu-ld),)
	CROSS := mips-linux-gnu-
else ifneq ($(call find-command,mips64-linux-gnu-ld),)
	CROSS := mips64-linux-gnu-
else ifneq ($(call find-command,mips64-elf-ld),)
	CROSS := mips64-elf-
else
  $(error Unable to detect a suitable MIPS toolchain installed.)
endif

UV ?= uv
PYTHON ?= $(UV) run python
SPLAT ?= $(UV) run splat

# IDO 5.3 is SGI's compiler, statically recompiled to x86-64 by decompals. It is
# fetched rather than committed; the pinned release is byte-identical to the
# copy this repo used to carry, so the build still matches.
IDO_DIR := tools/ido-5.3
IDO_VERSION := v1.2
IDO_TARBALL := ido-5.3-recomp-linux.tar.gz
IDO_SHA256 := ab5c741561f80913d58c8b074771f23941a3edd312505a8ebed6d1dfeb65e506
IDO_URL := https://github.com/decompals/ido-static-recomp/releases/download/$(IDO_VERSION)/$(IDO_TARBALL)

CC := $(IDO_DIR)/cc

AS := $(CROSS)as
LD := $(CROSS)ld
OBJCOPY := $(CROSS)objcopy
OBJDUMP := $(CROSS)objdump

CHECK_WARNINGS := -Wall -Wextra -Wno-format-security -Wno-unknown-pragmas -Wno-unused-parameter -Wno-unused-variable -Wno-missing-braces -Wno-int-conversion
CC_CHECK := gcc -fno-builtin -fsyntax-only -fsigned-char -std=gnu90 -D_LANGUAGE_C -D_FINALROM -DF3DEX_GBI -D__sgi -DNDEBUG $(CHECK_WARNINGS)

##### Flags #####
INCLUDES := -Iinclude -Ilibultra/include -Ilibultra/include/PR -Isrc -Isrc/libultra -I.

MIPSISA  := -mips2
OPTFLAGS := -O2

# libultra 2.0H was shipped as a per-directory build with different -O levels.
# Each level below was pinned by finding a function in that directory that
# compiles byte-exact at one level and at no other:
#   os    -O1  osVirtualToPhysical  (0x70 bytes at -O2/-O3, 0x80 at -O1)
#   io    -O1  __osSpDeviceBusy     (9 of 12 words wrong at -O2/-O3)
#   audio -O3  alSynAllocFX         (0xF0 bytes at -O1, 10 words wrong at -O2)
#   gu    -O2  guMtxL2F             (0x2D0 bytes at -O1, rescheduled at -O3)
# gu lands on the -O2 default; it is spelled out anyway so the evidence is not
# lost if the default ever changes.
$(BUILD_DIR)/src/libultra/audio/%.c.o: OPTFLAGS := -O3
$(BUILD_DIR)/src/libultra/gu/%.c.o:    OPTFLAGS := -O2
$(BUILD_DIR)/src/libultra/io/%.c.o:    OPTFLAGS := -O1
$(BUILD_DIR)/src/libultra/os/%.c.o:    OPTFLAGS := -O1

ASFLAGS := -EB -mtune=vr4300 -march=vr4300 -mabi=32 -Iinclude -I.
CFLAGS  := -G 0 -non_shared -Xfullwarn -Xcpluscomm $(INCLUDES) -Wab,-r4300_mul -woff 649,838,712 -D_LANGUAGE_C -D_FINALROM -DF3DEX_GBI -D__sgi -DNDEBUG
OBJCOPYFLAGS := --pad-to=0x2000000 --gap-fill=0x00

##### Files #####
BIN_FILES := $(foreach dir,$(BIN_DIRS),$(wildcard $(dir)/*.bin))
S_FILES   := $(foreach dir,$(ASM_DIRS),$(wildcard $(dir)/*.s))
C_FILES   := $(foreach dir,$(SRC_DIRS),$(wildcard $(dir)/*.c))

O_FILES := $(foreach file,$(S_FILES),$(BUILD_DIR)/$(file).o) \
           $(foreach file,$(C_FILES),$(BUILD_DIR)/$(file).o) \
           $(foreach file,$(BIN_FILES),$(BUILD_DIR)/$(file).o)

GLOBAL_ASM_C_FILES := $(shell grep -rl GLOBAL_ASM $(SRC_DIRS) 2>/dev/null | sort -u)
GLOBAL_ASM_O_FILES := $(foreach file,$(GLOBAL_ASM_C_FILES),$(BUILD_DIR)/$(file).o)

TARGET := $(BUILD_DIR)/$(BASENAME)
LD_SCRIPT := .splat/$(VERSION)/$(BASENAME).ld

FILE_ENCODING = Shift_JIS

##### Targets #####
default: all

all: $(TARGET).z64
	@sha1sum $(TARGET).z64
ifeq ($(COMPRESSED),yes)
	@sha1sum -c $(CONFIG_DIR)/$(BASENAME).sha1
else
	@sha1sum -c $(CONFIG_DIR)/$(BASENAME).uncompressed.sha1
endif

# Switching COMPRESSED has to force the ROM to be regenerated, otherwise make
# sees an up-to-date .z64 and checks it against the wrong sha1.
COMPRESSED_STAMP := $(BUILD_DIR)/.compressed-$(COMPRESSED)

$(COMPRESSED_STAMP):
	@mkdir -p $(dir $@)
	@rm -f $(BUILD_DIR)/.compressed-*
	@touch $@

$(TARGET).z64: $(TARGET).elf $(COMPRESSED_STAMP)
	$(OBJCOPY) -O binary $(OBJCOPYFLAGS) $< $@
ifeq ($(COMPRESSED),yes)
	$(PYTHON) tools/rommy.py compress --input $@ --output $@ --manifest $(CONFIG_DIR)/rommy.yaml --pad --verify
endif

$(TARGET).elf: $(O_FILES)
	@mkdir -p $(dir $@)
	$(LD) -T $(LD_SCRIPT) -Map $(TARGET).map -T .splat/$(VERSION)/undefined_syms_auto.ld -T .splat/$(VERSION)/undefined_funcs_auto.ld -T $(CONFIG_DIR)/overlay_syms.ld --no-check-sections --emit-relocs -o $@

# The standing checks. Each one was written after the bug it detects, and each
# was then run only when someone remembered it -- which is not a check.
#
# None of these needs a build, so `make check` is fast and safe to run at any
# time. They exit nonzero on disagreement, so the first failure stops the lot.
#
#   overlay_map.py --verify    the recovered load-address table still agrees
#                              with the five loads the boot path hardcodes.
#   fingerprint_risk.py        the set of fingerprinted libultra names that
#                              N64Recomp substitutes or skips has not changed
#                              under us -- an upstream bump can add one without
#                              touching this repo.
#   undefined_funcs_report.py  every absolute symbol splat could not attribute
#                              to a section is still accounted for. Needs the
#                              ELF, so it is skipped when there is no build.
check:
	$(PYTHON) tools/overlay_map.py --verify
	$(PYTHON) tools/fingerprint_risk.py
	@if [ -f $(TARGET).elf ]; then \
		$(PYTHON) tools/undefined_funcs_report.py --version $(VERSION); \
	else \
		echo "SKIP undefined_funcs_report.py -- no $(TARGET).elf (run make first)"; \
	fi

# Snapshot a known-good build for asm-differ to diff against.
expected: all
	rm -rf expected/build/$(VERSION)
	mkdir -p expected/build
	cp -r $(BUILD_DIR) expected/build/$(VERSION)

nuke:
	rm -rf asm bin build .splat expected
	rm -f $(CONFIG_DIR)/baserom.decompressed.z64

clean:
	rm -rf build

# splat.yaml is generated: edit tools/gen_splat_yaml.py and config/<ver>/file_boundaries.txt.
setup: $(CONFIG_DIR)/baserom.decompressed.z64 $(IDO_DIR)/cc
	$(PYTHON) tools/gen_splat_yaml.py --version $(VERSION)
	$(SPLAT) split $(CONFIG_DIR)/splat.yaml

$(IDO_DIR)/cc:
	@mkdir -p $(IDO_DIR)
	curl -fsSL -o $(IDO_DIR)/$(IDO_TARBALL) $(IDO_URL)
	echo "$(IDO_SHA256)  $(IDO_DIR)/$(IDO_TARBALL)" | sha256sum -c --quiet
	tar xzf $(IDO_DIR)/$(IDO_TARBALL) -C $(IDO_DIR)
	rm $(IDO_DIR)/$(IDO_TARBALL)
	@touch $@

# Decompress the retail ROM's Nisitenma-Ichigo archive so every file can be
# split and rebuilt independently. rommy.py round-trips byte-exactly.
$(CONFIG_DIR)/baserom.decompressed.z64: $(CONFIG_DIR)/baserom.z64
	$(PYTHON) tools/rommy.py decompress --input $< --output $@ --manifest $(CONFIG_DIR)/rommy.yaml --pad

##### Recipes #####
ifndef PERMUTER
$(GLOBAL_ASM_O_FILES): CC := tools/asm-processor/asm-processor --input-enc=utf-8 --output-enc=$(FILE_ENCODING) $(CC) -- $(AS) $(ASFLAGS) --
endif

$(BUILD_DIR)/%.c.o: %.c | $(IDO_DIR)/cc
	@mkdir -p $$(dirname $@)
	@$(CC_CHECK) $(INCLUDES) $<
ifdef PERMUTER
	$(CC) -c $(CFLAGS) $(OPTFLAGS) $(MIPSISA) -o $@ $<
else
	iconv -f UTF-8 -t $(FILE_ENCODING) $< > $@.encoded.c
	$(CC) -c $(CFLAGS) $(OPTFLAGS) $(MIPSISA) -o $@ $@.encoded.c
endif

$(BUILD_DIR)/%.s.o: %.s
	@mkdir -p $$(dirname $@)
ifdef PERMUTER
	$(AS) $(ASFLAGS) -o $@ $<
else
	iconv -f UTF-8 -t $(FILE_ENCODING) $< > $@.encoded.s
	$(AS) $(ASFLAGS) -o $@ $@.encoded.s
endif

$(BUILD_DIR)/%.bin.o: %.bin
	@mkdir -p $$(dirname $@)
	$(LD) -r -b binary -o $@ $<

.PHONY: default all check clean nuke setup expected
