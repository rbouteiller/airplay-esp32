#!/usr/bin/env bash
# Format all source files

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

# Find clang-format
CLANG_FORMAT=""
for cmd in clang-format clang-format-14 clang-format-15 clang-format-16; do
  if command -v "$cmd" &> /dev/null; then
    CLANG_FORMAT="$cmd"
    break
  fi
done

# Check common paths
if [ -z "$CLANG_FORMAT" ]; then
  for path in /opt/homebrew/bin/clang-format /usr/local/bin/clang-format; do
    if [ -x "$path" ]; then
      CLANG_FORMAT="$path"
      break
    fi
  done
fi

if [ -z "$CLANG_FORMAT" ]; then
  echo "Error: clang-format not found"
  echo ""
  echo "Install clang-format:"
  echo "  macOS:  brew install clang-format"
  echo "  Ubuntu: sudo apt install clang-format"
  echo "  Fedora: sudo dnf install clang-tools-extra"
  exit 1
fi

find main components -name "*.c" -o -name "*.h" | xargs "$CLANG_FORMAT" -i

echo "Formatted all source files"
