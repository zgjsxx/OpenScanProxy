#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="build"
VERBOSE="OFF"
LIST_ONLY="OFF"
REGEX=""

usage() {
  cat <<'EOF'
Usage:
  ./test.sh [options]

Options:
  --build-dir <dir>   Use a custom build directory (default: build)
  --verbose           Run ctest with -VV
  --list              List registered tests without running them
  --regex <expr>      Run only tests matching the regex
  -h, --help          Show this help message
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --build-dir)
      BUILD_DIR="${2:?missing value for --build-dir}"
      shift 2
      ;;
    --verbose)
      VERBOSE="ON"
      shift
      ;;
    --list)
      LIST_ONLY="ON"
      shift
      ;;
    --regex)
      REGEX="${2:?missing value for --regex}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

BUILD_DIR_ABS="$ROOT_DIR/$BUILD_DIR"
if [[ ! -d "$BUILD_DIR_ABS" ]]; then
  echo "Build directory does not exist: $BUILD_DIR_ABS" >&2
  exit 1
fi

CTEST_CMD=(ctest --output-on-failure)
if [[ "$VERBOSE" == "ON" ]]; then
  CTEST_CMD=(-VV --output-on-failure)
fi
if [[ "$LIST_ONLY" == "ON" ]]; then
  CTEST_CMD=(-N)
  if [[ "$VERBOSE" == "ON" ]]; then
    CTEST_CMD=(-N -VV)
  fi
fi
if [[ -n "$REGEX" ]]; then
  CTEST_CMD+=(-R "$REGEX")
fi

echo "==> Running tests from $BUILD_DIR_ABS"
(
  cd "$BUILD_DIR_ABS"
  ctest "${CTEST_CMD[@]}"
)
