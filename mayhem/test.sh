#!/usr/bin/env bash
#
# mayhem/test.sh — RUNS the known-answer probe (/mayhem/lk-kat, built by build.sh with the project's
# normal flags) over the LK modules the fuzz targets cover. Each check parses a fixed input and asserts
# the parsed values, so a program that is neutered to exit(0) produces no PASS lines and fails here.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SRC:=/mayhem}"
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# The probe is built by build.sh; a missing binary is a build failure, never a skip.
EXPECTED=29
if [ ! -x "$SRC/lk-kat" ]; then
  echo "lk-kat is missing: mayhem/build.sh did not build it" >&2
  emit_ctrf "lk-kat" 0 1
  exit 1
fi

out="$("$SRC/lk-kat" 2>&1)" ; echo "$out"
passed=$(printf '%s\n' "$out" | grep -c '^PASS ')
failed=$(printf '%s\n' "$out" | grep -c '^FAIL ')
# Fewer results than the probe defines means checks silently did not run.
if [ $(( passed + failed )) -lt "$EXPECTED" ]; then
  failed=$(( failed + EXPECTED - passed - failed ))
fi
emit_ctrf "lk-kat" "$passed" "$failed"
