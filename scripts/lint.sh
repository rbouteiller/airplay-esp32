#!/bin/bash
# Lint script for the project

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

# Find all C source files in main/
SOURCES=$(find main -name "*.c" -o -name "*.h")

echo "=== Running clang-format check ==="
for file in $SOURCES; do
  if ! clang-format --dry-run --Werror "$file" 2>/dev/null; then
    echo "Format issues in: $file"
    NEED_FORMAT=1
  fi
done

if [ -n "$NEED_FORMAT" ]; then
  echo ""
  echo "Run 'clang-format -i main/**/*.c main/**/*.h' to fix formatting"
  exit 1
fi

echo "All files formatted correctly"
