#!/usr/bin/env bash
#
# mayhem/build.sh — builds the LK modules that parse untrusted data (libfdt, lib/devicetree, miniz,
# lib/elf, lib/cmdline) for the host, with a small shim (mayhem/host) in place of the kernel. Builds:
#   1. one sanitized libFuzzer binary + `-standalone` reproducer per harness in /mayhem
#   2. the known-answer probe /mayhem/lk-kat with NORMAL flags (what mayhem/test.sh runs)
# Re-runnable and offline: it only reads the checkout and the image's toolchain.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${SRC:=/mayhem}"
: "${STANDALONE_FUZZ_MAIN:?base image must provide STANDALONE_FUZZ_MAIN}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS

cd "$SRC"
OUT="$SRC/build-mayhem"          # gitignored by upstream's `build-*`
rm -rf "$OUT"
mkdir -p "$OUT/fuzz" "$OUT/kat"

# What the host shim in mayhem/host/include stands in for: LK as built for a 64-bit target with
# DEBUG=2 (DEBUG_ASSERT enabled), plus the cmdline module's test hook that resets its global state.
DEFS="-DLK_DEBUGLEVEL=2 -DIS_64BIT=1 -DARCH_X86_64=1 -DWITH_TESTS=1"
INCS="-I$SRC/mayhem/host/include -I$SRC/top/include \
 -I$SRC/external/lib/fdt/include -I$SRC/external/lib/miniz/include \
 -I$SRC/lib/devicetree/include -I$SRC/lib/devicetree/include/lib -I$SRC/lib/elf/include -I$SRC/lib/cmdline/include"
WARN="-w"   # upstream code is built for its own toolchain; silence its warnings here

LIB_SRCS=(
  external/lib/fdt/fdt.c external/lib/fdt/fdt_addresses.c external/lib/fdt/fdt_check.c
  external/lib/fdt/fdt_empty_tree.c external/lib/fdt/fdt_overlay.c external/lib/fdt/fdt_ro.c
  external/lib/fdt/fdt_rw.c external/lib/fdt/fdt_strerror.c external/lib/fdt/fdt_sw.c
  external/lib/fdt/fdt_wip.c
  external/lib/miniz/miniz.c
  lib/devicetree/devicetree.c
  lib/elf/elf.c
  lib/cmdline/cmdline.c
  mayhem/host/support.c
)

# Fuzzed code: sanitized, DWARF<=3, SanCov via fuzzer-no-link (kept even when SANITIZER_FLAGS is empty).
FUZZ_CFLAGS="-O1 $SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS"
# Oracle code: the project's normal flags — no sanitizer, no -gdwarf-3.
KAT_CFLAGS="-O2"

pids=()
for s in "${LIB_SRCS[@]}"; do
  o="${s//\//_}.o"
  # miniz deliberately does unaligned 16/32/64-bit loads (MINIZ_USE_UNALIGNED_LOADS_AND_STORES) in
  # tdefl's match finder, and forms `NULL + 0` on the first call of every heap inflate. Both are
  # benign on this target and would halt almost every input: relax just those two UBSan checks, on
  # that one file.
  extra=""
  [ "$s" = external/lib/miniz/miniz.c ] && extra="-fno-sanitize=pointer-overflow,alignment"
  # su32() does `u8 << 24` into an int: UB for any byte >= 0x80, so for the 0xd0 of every DTB magic.
  [ "$s" = lib/devicetree/devicetree.c ] && extra="-fno-sanitize=shift-base"
  # shellcheck disable=SC2086
  $CC $FUZZ_CFLAGS $extra $DEFS $INCS $WARN -c "$s" -o "$OUT/fuzz/$o" &
  # shellcheck disable=SC2086
  $CC $KAT_CFLAGS $DEFS $INCS $WARN -c "$s" -o "$OUT/kat/$o" &
  while [ "$(jobs -rp | wc -l)" -ge "$MAYHEM_JOBS" ]; do wait -n; done
done
wait

# Leak sanitizer off for every ASan target (ASan and UBSan stay on).
# shellcheck disable=SC2086
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o "$OUT/fuzz/lsan_off.o"
# shellcheck disable=SC2086
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -x c -c "$STANDALONE_FUZZ_MAIN" -o "$OUT/fuzz/standalone_main.o"

# Each harness links only the library objects it needs.
declare -A NEEDS=(
  [fuzz_fdt]="external_lib_fdt_*"
  [fuzz_devicetree]="lib_devicetree_devicetree.c.o"
  [fuzz_miniz]="external_lib_miniz_miniz.c.o"
  [fuzz_elf]="lib_elf_elf.c.o"
  [fuzz_cmdline]="lib_cmdline_cmdline.c.o"
)
for h in "${!NEEDS[@]}"; do
  # shellcheck disable=SC2086
  objs=$(cd "$OUT/fuzz" && ls ${NEEDS[$h]} | sed "s|^|$OUT/fuzz/|")
  support="$OUT/fuzz/mayhem_host_support.c.o"
  # shellcheck disable=SC2086
  $CC $FUZZ_CFLAGS $DEFS $INCS $WARN -c "mayhem/harness/$h.c" -o "$OUT/fuzz/$h.o"
  # shellcheck disable=SC2086
  $CC $SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS $LIB_FUZZING_ENGINE \
      "$OUT/fuzz/$h.o" $objs "$support" "$OUT/fuzz/lsan_off.o" -o "$SRC/$h"
  # shellcheck disable=SC2086
  $CC $SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS \
      "$OUT/fuzz/standalone_main.o" "$OUT/fuzz/$h.o" $objs "$support" "$OUT/fuzz/lsan_off.o" -o "$SRC/$h-standalone"
done

# Known-answer probe for test.sh, dynamically linked and unsanitized.
# shellcheck disable=SC2086
$CC $KAT_CFLAGS $DEFS $INCS $WARN mayhem/kat/lk_kat.c "$OUT"/kat/*.o -o "$SRC/lk-kat"
