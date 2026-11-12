#!/bin/bash
# Run clang-tidy over main/ and components/ sources.
# Usage: lint.sh [--fix] [file.c ...]   (no files: all sources)
#
# Needs an ESP-IDF environment. A stock clang-tidy can't parse the GCC
# Xtensa/RISC-V build and checks nothing, so each config is configured (not
# built) with ESP-IDF's clang toolchain and linted with esp-clang.
#
# No config builds every file; CONFIGS together cover all sources, each
# linted once. Uncovered sources and parse errors fail. Findings fail unless
# a directory's .clang-tidy says otherwise.

set -euo pipefail

# Compile debug logs in: log-only values aren't dead stores, and log calls
# get checked.
LINT_OPTIONS="CONFIG_LOG_MAXIMUM_LEVEL_VERBOSE=y"

# name | target | sdkconfig defaults | extra options for the lint only
CONFIGS=(
  "esp32s3|esp32s3|config/sdkconfig.defaults;config/sdkconfig.defaults.esp32s3|"
  "audio-brick-dual-uac|esp32s3|config/sdkconfig.defaults;config/sdkconfig.defaults.esparagus-audio-brick-dual-dac;config/sdkconfig.defaults.uac|"
  "squeezeamp-bt|esp32|config/sdkconfig.defaults;config/sdkconfig.defaults.squeezeamp;config/sdkconfig.defaults.bt|"
  "hifi-esp32-plus-bt|esp32|config/sdkconfig.defaults;config/sdkconfig.defaults.hifi-esp32-plus;config/sdkconfig.defaults.bt|"
  # ES8388 has no board; build its driver here.
  "waveshare-esp32s3|esp32s3|config/sdkconfig.defaults;config/sdkconfig.defaults.waveshare-esp32s3|CONFIG_DAC_ES8388=y"
  "wrover-spdif|esp32|config/sdkconfig.defaults;config/sdkconfig.defaults.wrover;config/sdkconfig.defaults.spdif|"
  "esp32s2-usb|esp32s2|config/sdkconfig.defaults;config/sdkconfig.defaults.esp32s2;config/sdkconfig.defaults.usb|"
  "esp32c5|esp32c5|config/sdkconfig.defaults;config/sdkconfig.defaults.esp32c5|"
  # clang can't target P4 rev 3+; the revision doesn't matter to linting.
  "esp32p4|esp32p4|config/sdkconfig.defaults;config/sdkconfig.defaults.esp32p4|CONFIG_ESP32P4_SELECTS_REV_LESS_V3=y"
  "loud-esp32-s3|esp32s3|config/sdkconfig.defaults;config/sdkconfig.defaults.loud-esp32-s3|"
  "hifi-esp32-s3|esp32s3|config/sdkconfig.defaults;config/sdkconfig.defaults.hifi-esp32-s3|"
  "louder-esp32-s3-mini|esp32s3|config/sdkconfig.defaults;config/sdkconfig.defaults.louder-esp32-s3-mini|"
  "amped-esparagus-plus-s3|esp32s3|config/sdkconfig.defaults;config/sdkconfig.defaults.amped-esparagus-plus-s3|"
  "software-eq|esp32s3|config/sdkconfig.defaults;config/sdkconfig.defaults.esp32s3;config/sdkconfig.defaults.uac;config/sdkconfig.defaults.software-eq|"
)

FIX=""
if [ "${1:-}" = "--fix" ]; then
  FIX="--fix-errors"
  shift
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if ! command -v idf.py >/dev/null; then
  echo "lint: run from an ESP-IDF environment (. \$IDF_PATH/export.sh)" >&2
  exit 1
fi
if ! clang-tidy --version 2>/dev/null | grep -q Espressif; then
  python "$IDF_PATH/tools/idf_tools.py" install esp-clang
  eval "$(python "$IDF_PATH/tools/idf_tools.py" export)"
fi

# Each config sets its own target; an inherited one (CI exports it) clashes.
unset IDF_TARGET

# Sources, minus vendored u8g2.
sources() {
  find main components -path components/u8g2 -prune -o \
    -path components/u8g2-hal-esp-idf -prune -o -name '*.c' -print | sort
}

if [ $# -gt 0 ]; then
  wanted=$(printf '%s\n' "$@" | grep '\.c$' | sort -u || true)
else
  wanted=$(sources)
fi
[ -n "$wanted" ] || exit 0

# Report project headers too.
root_re=$(printf '%s' "$ROOT" | sed 's/[]\.[^$*+?(){}|]/\\&/g')
TIDY=(clang-tidy --quiet "--header-filter=^$root_re/(main|components)/"
  "--exclude-header-filter=^$root_re/components/u8g2")
[ -n "$FIX" ] && TIDY+=("$FIX")
# --fix runs serially: fixes to shared headers would race.
JOBS=$(getconf _NPROCESSORS_ONLN)
[ -z "$FIX" ] || JOBS=1

left="$wanted"
status=0
for spec in "${CONFIGS[@]}"; do
  [ -n "$left" ] || break
  IFS='|' read -r name target defaults extra <<<"$spec"
  dir="build-lint/$name"
  mkdir -p "$dir"
  tr ' ' '\n' <<<"$LINT_OPTIONS $extra" >"$dir/sdkconfig.lint"
  rm -f "$dir/sdkconfig" # re-derive from the defaults on every run
  if ! idf.py -B "$dir" -DIDF_TOOLCHAIN=clang -DIDF_TARGET="$target" \
    -DSDKCONFIG="$dir/sdkconfig" \
    -DSDKCONFIG_DEFAULTS="$defaults;$dir/sdkconfig.lint" \
    reconfigure >"$dir/configure.log" 2>&1; then
    echo "lint: configuring $name failed ($dir/configure.log):" >&2
    tail -n 20 "$dir/configure.log" >&2
    exit 1
  fi

  built=$(python - "$dir/compile_commands.json" "$ROOT/" <<'EOF'
import json, sys
db, root = sys.argv[1], sys.argv[2]
print("\n".join(sorted({e["file"][len(root):] for e in json.load(open(db))
                        if e["file"].startswith(root)})))
EOF
  )
  mine=$(comm -12 <(echo "$left") <(echo "$built"))
  [ -n "$mine" ] || continue
  left=$(comm -23 <(echo "$left") <(echo "$mine"))

  echo "lint: $(echo "$mine" | wc -l | tr -d ' ') file(s) under $name"
  # Buffer per file so output doesn't interleave; print any finding.
  # shellcheck disable=SC2016 # expanded by the inner shell
  if ! echo "$mine" | xargs -P "$JOBS" -I{} sh -c '
    out=$("$@" 2>&1); rc=$?
    case "$out" in *": warning: "* | *": error: "*) printf "%s\n\n" "$out" ;; esac
    exit $rc
  ' sh "${TIDY[@]}" -p "$dir" {}; then
    status=1
  fi
done

if [ -n "$left" ]; then
  echo "lint: no config compiles these, so they were not checked:" >&2
  # shellcheck disable=SC2086 # one path per word
  printf '  %s\n' $left >&2
  status=1
fi

if [ "$status" -ne 0 ]; then
  echo "clang-tidy found issues"
  exit 1
fi
echo "All files pass clang-tidy checks"
