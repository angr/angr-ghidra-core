"""Drive the angr core through the full protocol on multiple architectures.

The oracle stands in for Ghidra per-arch (right pspec/cspec/tspec via archmap),
and the core infers the arch purely from those documents. Each case decompiles a
function and checks a plausible C function came back; where the binary is
fauxware, its library calls should also resolve to names.
"""

import os

import pytest

from angr_ghidra_core.harness.session import ANGR_CORE, DecompSession

BINROOT = "/workspace/binaries/tests"

# (arch dir, binary, function, expect_named_calls)
CASES = [
    ("x86_64", "fauxware", "main", True),
    ("i386", "fauxware", "main", True),
    ("armel", "fauxware", "main", True),
    ("mips", "fauxware", "main", True),       # big-endian MIPS32
    ("mipsel", "fauxware", "main", True),     # little-endian MIPS32
    ("ppc", "fauxware", "main", True),        # big-endian PPC32
    ("aarch64", "test_arrays", "main", False),
    ("mips64", "test_arrays", "main", False),
    # Known-unsupported: Thumb (odd entry needs consistent T-bit handling) and
    # PPC64 ELFv1 (the "main" symbol is a function descriptor, not code).
    pytest.param("armhf", "fauxware", "main", True,
                 marks=pytest.mark.xfail(reason="Thumb mode not yet supported", strict=False)),
    pytest.param("ppc64", "fauxware", "main", True,
                 marks=pytest.mark.xfail(reason="PPC64 ELFv1 function descriptors", strict=False)),
]

pytestmark = pytest.mark.skipif(
    not os.path.exists(ANGR_CORE[1]), reason="core not available")


@pytest.mark.parametrize("arch,binary,func,expect_named", CASES,
                         ids=[c[0] if not hasattr(c, "values") else c.values[0] for c in CASES])
def test_decompiles(arch, binary, func, expect_named, tmp_path):
    path = f"{BINROOT}/{arch}/{binary}"
    if not os.path.exists(path):
        pytest.skip(f"{path} not present")
    os.environ["ANGR_GHIDRA_CACHE"] = str(tmp_path / "cache")
    s = DecompSession(path, core=ANGR_CORE)
    try:
        c = s.decompile(func).c
    finally:
        s.close()
    # a real function body: a signature line and a brace
    assert func in c or "(" in c.splitlines()[0]
    assert "{" in c and "}" in c
    if expect_named:
        assert any(name in c for name in
                   ("puts", "read", "strcmp", "printf", "authenticate", "open")), \
            f"expected a resolved library-call name in:\n{c}"
