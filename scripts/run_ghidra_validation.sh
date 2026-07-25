#!/usr/bin/env bash
# Validate the angr-backed core against the REAL Ghidra Java decoders, headless.
#
# Builds nothing; assumes a Ghidra installation at $GHIDRA_DIST with the angr
# launcher installed as its Decompiler `decompile` binary (use ./install.sh, or
# see README "Ghidra testing").
#
# Exits non-zero unless the validation reports failures=0, so it can gate CI.
#
# Usage: scripts/run_ghidra_validation.sh [binary] [function]
#   $GHIDRA_DIST  Ghidra installation (default: the dev tree's built dist)
#   $JAVA_HOME    JDK to run Ghidra with (default: /workspace/jdk if present)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GHIDRA_DIST="${GHIDRA_DIST:-/workspace/ghidra/build/dist/ghidra_12.2_DEV}"
BIN="${1:-${ANGR_GHIDRA_TEST_BINARIES:-/workspace/binaries/tests}/x86_64/fauxware}"
FUNC="${2:-main}"

if [ -n "${JAVA_HOME:-}" ]; then
    export JAVA_HOME PATH="$JAVA_HOME/bin:$PATH"
elif [ -d /workspace/jdk ]; then
    export JAVA_HOME=/workspace/jdk PATH="/workspace/jdk/bin:$PATH"
fi

[ -x "$GHIDRA_DIST/support/analyzeHeadless" ] || {
    echo "error: no Ghidra at '$GHIDRA_DIST' (set \$GHIDRA_DIST)" >&2; exit 1; }
[ -f "$BIN" ] || { echo "error: no test binary at '$BIN'" >&2; exit 1; }

PROJ="$(mktemp -d)"
trap 'rm -rf "$PROJ"' EXIT

OUT="$PROJ/headless.log"
"$GHIDRA_DIST/support/analyzeHeadless" "$PROJ" tmpproj \
    -import "$BIN" \
    -scriptPath "$HERE/ghidra_validation" \
    -postScript ValidateAngrCore.java "$FUNC" \
    -deleteProject > "$OUT" 2>&1 || true

grep -E "ANGR_CORE_VALIDATION|Decoding error" "$OUT" || true

if grep -q "ANGR_CORE_VALIDATION: DONE failures=0" "$OUT"; then
    echo "PASS: $(basename "$BIN") $FUNC decompiled through real Ghidra with no failures"
    exit 0
fi
echo "FAIL: validation did not report failures=0 (full log below)" >&2
tail -40 "$OUT" >&2
exit 1
