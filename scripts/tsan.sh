#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

BUILD_DIR=build-tsan ENABLE_TSAN=ON "$SCRIPT_DIR/configure.sh"
BUILD_DIR=build-tsan "$SCRIPT_DIR/test.sh"
