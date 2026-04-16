#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="build"
BUILD_TYPE="Debug"
BUILD_TESTING="ON"
RUN_TESTS="OFF"
CLEAN_BUILD="OFF"
VERBOSE_BUILD="OFF"
TARGET_NAME=""
GENERATOR=""
JOBS=""
EXTRA_CMAKE_ARGS=()

usage() {
  cat <<'EOF'
Usage:
  ./build.sh [options]

Options:
  --debug                 Build with CMAKE_BUILD_TYPE=Debug (default)
  --release               Build with CMAKE_BUILD_TYPE=Release
  --build-dir <dir>       Use a custom build directory
  --tests                 Enable unit test targets (default)
  --no-tests              Disable unit test targets
  --run-tests             Run ctest after a successful build
  --clean                 Remove the build directory before configuring
  --verbose               Use verbose build output
  --target <name>         Build a specific target instead of the default all target
  --generator <name>      Pass an explicit CMake generator
  -j, --jobs <n>          Parallel build jobs passed to cmake --build
  --cmake-arg <arg>       Append an extra argument to the CMake configure step
  -h, --help              Show this help message

Examples:
  ./build.sh
  ./build.sh --release --run-tests
  ./build.sh --build-dir build-test --no-tests
  ./build.sh --target openscanproxy --generator Ninja
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --debug)
      BUILD_TYPE="Debug"
      shift
      ;;
    --release)
      BUILD_TYPE="Release"
      shift
      ;;
    --build-dir)
      BUILD_DIR="${2:?missing value for --build-dir}"
      shift 2
      ;;
    --tests)
      BUILD_TESTING="ON"
      shift
      ;;
    --no-tests)
      BUILD_TESTING="OFF"
      shift
      ;;
    --run-tests)
      RUN_TESTS="ON"
      shift
      ;;
    --clean)
      CLEAN_BUILD="ON"
      shift
      ;;
    --verbose)
      VERBOSE_BUILD="ON"
      shift
      ;;
    --target)
      TARGET_NAME="${2:?missing value for --target}"
      shift 2
      ;;
    --generator)
      GENERATOR="${2:?missing value for --generator}"
      shift 2
      ;;
    -j|--jobs)
      JOBS="${2:?missing value for $1}"
      shift 2
      ;;
    --cmake-arg)
      EXTRA_CMAKE_ARGS+=("${2:?missing value for --cmake-arg}")
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

if [[ "$CLEAN_BUILD" == "ON" ]]; then
  rm -rf "$BUILD_DIR_ABS"
fi

mkdir -p "$BUILD_DIR_ABS"

CONFIGURE_CMD=(cmake -S "$ROOT_DIR" -B "$BUILD_DIR_ABS" "-DCMAKE_BUILD_TYPE=$BUILD_TYPE" "-DBUILD_TESTING=$BUILD_TESTING")
if [[ -n "$GENERATOR" ]]; then
  CONFIGURE_CMD+=(-G "$GENERATOR")
fi
if [[ ${#EXTRA_CMAKE_ARGS[@]} -gt 0 ]]; then
  CONFIGURE_CMD+=("${EXTRA_CMAKE_ARGS[@]}")
fi

echo "==> Configuring"
printf '    %q ' "${CONFIGURE_CMD[@]}"
printf '\n'
"${CONFIGURE_CMD[@]}"

BUILD_CMD=(cmake --build "$BUILD_DIR_ABS")
if [[ -n "$TARGET_NAME" ]]; then
  BUILD_CMD+=(--target "$TARGET_NAME")
fi
if [[ -n "$JOBS" ]]; then
  BUILD_CMD+=(--parallel "$JOBS")
else
  BUILD_CMD+=(--parallel)
fi
if [[ "$VERBOSE_BUILD" == "ON" ]]; then
  BUILD_CMD+=(--verbose)
fi

echo "==> Building"
printf '    %q ' "${BUILD_CMD[@]}"
printf '\n'
"${BUILD_CMD[@]}"

if [[ "$RUN_TESTS" == "ON" ]]; then
  if [[ "$BUILD_TESTING" != "ON" ]]; then
    echo "Cannot run tests because BUILD_TESTING is OFF" >&2
    exit 1
  fi
  echo "==> Running tests"
  (
    cd "$BUILD_DIR_ABS"
    ctest --output-on-failure
  )
fi

echo "==> Done"
echo "    Build directory: $BUILD_DIR_ABS"
echo "    Build type: $BUILD_TYPE"
echo "    BUILD_TESTING: $BUILD_TESTING"
