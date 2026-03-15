#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-build}"
APP_PATH="$ROOT_DIR/$BUILD_DIR/cpp_dns_app"

cmake --build "$ROOT_DIR/$BUILD_DIR" --parallel
exec "$APP_PATH"
