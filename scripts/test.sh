#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-build}"

cmake --build "$ROOT_DIR/$BUILD_DIR" --parallel
ctest --test-dir "$ROOT_DIR/$BUILD_DIR" --output-on-failure
