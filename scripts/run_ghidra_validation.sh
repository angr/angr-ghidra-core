#!/usr/bin/env bash
# Validate the angr-backed core against the REAL Ghidra Java decoders, headless.
#
# Builds nothing; assumes a Ghidra dist at $GHIDRA_DIST with the angr launcher
# (launcher/target/release/decompile) installed as its Decompiler `decompile`
# binary (see README "Ghidra testing").
#
# Usage: scripts/run_ghidra_validation.sh [binary] [function]
set -euo pipefail

JAVA_HOME="${JAVA_HOME:-/workspace/jdk}"
GHIDRA_DIST="${GHIDRA_DIST:-/workspace/ghidra/build/dist/ghidra_12.2_DEV}"
BIN="${1:-/workspace/binaries/tests/x86_64/fauxware}"
FUNC="${2:-main}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

export JAVA_HOME PATH="$JAVA_HOME/bin:$PATH"
export ANGR_GHIDRA_PYTHON="${ANGR_GHIDRA_PYTHON:-/workspace/angr-venv/bin/python}"
export ANGR_GHIDRA_CORE="${ANGR_GHIDRA_CORE:-$HERE/bin/angr-decompile}"

PROJ="$(mktemp -d)"
trap 'rm -rf "$PROJ"' EXIT
"$GHIDRA_DIST/support/analyzeHeadless" "$PROJ" tmpproj \
    -import "$BIN" \
    -scriptPath "$HERE/ghidra_validation" \
    -postScript ValidateAngrCore.java "$FUNC" \
    -deleteProject 2>&1 | grep -E "ANGR_CORE_VALIDATION|Decoding error"
