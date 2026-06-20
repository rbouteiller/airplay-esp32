#!/usr/bin/env bash
# Format all source files, or check them with --check.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
EXPECTED_CLANG_FORMAT_VERSION="${EXPECTED_CLANG_FORMAT_VERSION:-22.1.4}"

cd "$PROJECT_DIR"

MODE="format"
if [[ "${1:-}" == "--check" ]]; then
  MODE="check"
elif [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  echo "Usage: scripts/format.sh [--check]"
  exit 0
elif [[ $# -gt 0 ]]; then
  echo "Unknown argument: $1" >&2
  echo "Usage: scripts/format.sh [--check]" >&2
  exit 1
fi

resolve_candidate() {
  local candidate="$1"

  if [[ "$candidate" == */* ]]; then
    [[ -x "$candidate" ]] && printf '%s\n' "$candidate"
  elif command -v "$candidate" >/dev/null 2>&1; then
    command -v "$candidate"
  fi
}

format_version() {
  "$1" --version | sed -E 's/.*version ([0-9]+(\.[0-9]+)*).*/\1/'
}

candidates=()
if [[ -n "${CLANG_FORMAT:-}" ]]; then
  candidates+=("$CLANG_FORMAT")
else
  candidates+=(
    "clang-format"
    "$HOME/.local/bin/clang-format"
    "clang-format-22"
    "/opt/homebrew/opt/llvm/bin/clang-format"
    "/usr/local/opt/llvm/bin/clang-format"
    "/opt/homebrew/opt/llvm@22/bin/clang-format"
    "/usr/local/opt/llvm@22/bin/clang-format"
  )
fi

CLANG_FORMAT_BIN=""
for candidate in "${candidates[@]}"; do
  resolved="$(resolve_candidate "$candidate" || true)"
  if [[ -n "$resolved" &&
        "$(format_version "$resolved")" == "$EXPECTED_CLANG_FORMAT_VERSION" ]]; then
    CLANG_FORMAT_BIN="$resolved"
    break
  fi
done

if [[ -z "$CLANG_FORMAT_BIN" ]]; then
  echo "Error: clang-format ${EXPECTED_CLANG_FORMAT_VERSION} is required." >&2
  echo "" >&2
  echo "Install it with:" >&2
  echo "  python3 -m pip install --user -r requirements-dev.txt" >&2
  echo "" >&2
  echo "Or set CLANG_FORMAT=/path/to/clang-format-${EXPECTED_CLANG_FORMAT_VERSION}." >&2
  exit 1
fi

FORMAT_ARGS=(-i)
if [[ "$MODE" == "check" ]]; then
  FORMAT_ARGS=(--dry-run --Werror)
fi

find main components -path components/u8g2 -prune -o \( -name "*.c" -o -name "*.h" \) -print0 \
  | xargs -0 "$CLANG_FORMAT_BIN" "${FORMAT_ARGS[@]}"

if [[ "$MODE" == "check" ]]; then
  echo "All source files are clang-formatted"
else
  echo "Formatted all source files"
fi
