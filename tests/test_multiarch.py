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

# (arch dir, binary, function, expect_named_calls, expect_fully_lifted)
# expect_fully_lifted=False tolerates the odd instruction angr's lifter can't
# handle for that ISA (not a mode/arch-resolution error).
CASES = [
    ("x86_64", "fauxware", "main", True, True),
    ("i386", "fauxware", "main", True, True),
    ("armel", "fauxware", "main", True, True),
    ("mips", "fauxware", "main", True, True),       # big-endian MIPS32
    ("mipsel", "fauxware", "main", True, True),     # little-endian MIPS32
    ("ppc", "fauxware", "main", True, True),        # big-endian PPC32
    ("armhf", "fauxware", "main", True, True),      # Thumb-2 (T-mode via getPcode)
    ("aarch64", "test_arrays", "main", False, True),
    ("mips64", "test_arrays", "main", False, False),  # one MIPS64 insn angr can't lift
    # Known-unsupported: PPC64 ELFv1 (the "main" symbol is a function descriptor,
    # not code).
    pytest.param("ppc64", "fauxware", "main", True, True,
                 marks=pytest.mark.xfail(reason="PPC64 ELFv1 function descriptors", strict=False)),
]

pytestmark = pytest.mark.skipif(
    not os.path.exists(ANGR_CORE[1]), reason="core not available")


@pytest.mark.parametrize("arch,binary,func,expect_named,expect_lifted", CASES,
                         ids=[c[0] if not hasattr(c, "values") else c.values[0] for c in CASES])
def test_decompiles(arch, binary, func, expect_named, expect_lifted, tmp_path):
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
    # guard against confidently-wrong output (e.g. Thumb bytes decoded as ARM):
    # angr emits this marker when it can't lift an instruction
    if expect_lifted:
        assert "unsupported instruction" not in c, f"undecoded instructions in:\n{c}"
    if expect_named:
        assert any(name in c for name in
                   ("puts", "read", "strcmp", "printf", "authenticate", "open")), \
            f"expected a resolved library-call name in:\n{c}"
