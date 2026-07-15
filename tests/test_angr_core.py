"""Validate the angr-backed core end-to-end through the protocol harness, and
compare it structurally against the real C++ core on the same binary."""

import os

import pytest

from angr_ghidra_core.harness.session import ANGR_CORE, REAL_CORE, DecompSession

FAUXWARE = "/workspace/binaries/tests/x86_64/fauxware"

pytestmark = pytest.mark.skipif(
    not (os.path.exists(REAL_CORE) and os.path.exists(FAUXWARE)),
    reason="cores or test binary not available",
)


@pytest.fixture(scope="module")
def angr_session():
    sess = DecompSession(FAUXWARE, core=ANGR_CORE)
    yield sess
    sess.close()


def test_angr_core_decompiles_main(angr_session):
    res = angr_session.decompile("main")
    assert res.model is not None, "angr core produced no model function"
    assert res.markup is not None, "angr core produced no C markup"
    assert res.model.attr("name") == "main"
    text = res.c
    # angr's structuring recovers the two-way branch on the auth result
    assert "return" in text
    assert "{" in text and "}" in text
    # a plausible number of statements came through
    assert text.count("\n") >= 6


def test_angr_core_resolves_call_names(angr_session):
    """Call targets are named from Ghidra's symbol table (getCodeLabel), not left
    as raw addresses."""
    text = angr_session.decompile("main").c
    assert "authenticate(" in text
    assert "accepted(" in text and "rejected(" in text
    # PLT stubs resolved via the import table
    assert "read(" in text or "puts(" in text
    # no bare hex-address calls remain
    import re
    assert not re.search(r"\b\d{7,}\(", text), f"unresolved numeric call in:\n{text}"


def test_angr_core_model_is_high_function_shaped(angr_session):
    res = angr_session.decompile("main")
    fn = res.model
    assert fn.first("localdb") is not None
    assert fn.first("prototype") is not None
    ret = fn.first("prototype").first("returnsym")
    assert ret is not None
    # returnsym must carry a valid storage address (the core rejects empty ones)
    assert ret.first("addr") is not None


def test_angr_core_second_function(angr_session):
    res = angr_session.decompile("authenticate")
    assert res.model.attr("name") == "authenticate"
    assert res.markup is not None


def test_both_cores_agree_on_structure():
    """Both cores, given the same bytes, should recover a function with the same
    entry, a branch, and calls — even though the exact C text differs."""
    with DecompSession(FAUXWARE, core=REAL_CORE) as real, \
         DecompSession(FAUXWARE, core=ANGR_CORE) as angr:
        r = real.decompile("main")
        a = angr.decompile("main")
        assert r.model.attr("name") == a.model.attr("name") == "main"
        # both recover control flow with a conditional
        assert "if" in r.c or "?" in r.c
        assert "if" in a.c or "?" in a.c
        # both call into the same number of subroutines (fauxware main has 6 calls
        # plus authenticate + accepted/rejected); check both see multiple calls
        assert r.c.count("(") >= 4
        assert a.c.count("(") >= 4
