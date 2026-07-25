"""Shared test paths.

The test corpus is angr's `binaries` repository (https://github.com/angr/binaries).
It lives at /workspace/binaries in the dev tree; set $ANGR_GHIDRA_TEST_BINARIES to
point at a checkout anywhere else (CI clones it into the runner's temp dir).
"""

import os

BINROOT = os.environ.get("ANGR_GHIDRA_TEST_BINARIES", "/workspace/binaries/tests")


def binary(relpath: str) -> str:
    """Absolute path to a test binary, e.g. binary("x86_64/fauxware")."""
    return os.path.join(BINROOT, relpath)
