#!/bin/bash
# Lint script for the project

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

# Ensure clang-tidy is available (install via brew if needed)
if ! command -v clang-tidy &>/dev/null; then
  if command -v brew &>/dev/null; then
    echo "clang-tidy not found, installing llvm via brew..."
    brew install llvm
    export PATH="$(brew --prefix llvm)/bin:$PATH"
  else
    echo "Error: clang-tidy not found and brew is not available to install it"
    exit 1
  fi
fi

# Find all C source files in main/
SOURCES=$(find main -name "*.c" -o -name "*.h")

echo "=== Running clang-tidy ==="
ERRORS=0
for file in $SOURCES; do
  if ! clang-tidy "$file" -- -I main -I main/audio -I main/rtsp 2>/dev/null; then
    ERRORS=1
  fi
done

if [ "$ERRORS" -ne 0 ]; then
  echo ""
  echo "clang-tidy found issues"
  exit 1
fi

echo "All files pass clang-tidy checks"
