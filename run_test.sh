#!/usr/bin/env bash
set -euo pipefail

clear && ./scripts/configure.sh && ./scripts/test.sh
