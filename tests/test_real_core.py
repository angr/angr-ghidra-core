"""Integration test: drive the real C++ decompiler core with the Python harness."""

import os

import pytest

from angr_ghidra_core.ghidra_wire import PackedEncoder, ids
from angr_ghidra_core.ghidra_wire.client import DecompClient
from angr_ghidra_core.ghidra_wire.clang import render_c, split_decompile_response
from angr_ghidra_core.ghidra_wire.dump import parse_tree
from angr_ghidra_core.harness.oracle import SPACE_RAM, PypcodeOracle

CORE = "/workspace/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/ghidra_opt"
FAUXWARE = "/workspace/binaries/tests/x86_64/fauxware"

pytestmark = pytest.mark.skipif(
    not (os.path.exists(CORE) and os.path.exists(FAUXWARE)),
    reason="real core or test binary not available",
)


@pytest.fixture(scope="module")
def session():
    oracle = PypcodeOracle(FAUXWARE)
    client = DecompClient(CORE, oracle)
    client.register_program(oracle.pspec(), oracle.cspec(), oracle.tspec(), oracle.coretypes())
    client.set_action("decompile", "")
    client.set_action("", "tree")
    client.set_action("", "c")
    yield oracle, client
    client.close()


def decompile(oracle, client, name):
    func = next(f for f in oracle.functions.values() if f.name == name)
    enc = PackedEncoder()
    enc.open_element(ids.ELEM_ADDR)
    enc.write_space(ids.ATTRIB_SPACE, SPACE_RAM)
    enc.write_unsigned(ids.ATTRIB_OFFSET, func.addr)
    enc.close_element(ids.ELEM_ADDR)
    result = client.decompile_at(enc)
    assert result, f"empty decompile response (error: {client.error_message})"
    roots = parse_tree(result)
    model, markup = split_decompile_response(roots)
    return model, markup


def test_register_program(session):
    _, client = session
    assert client.arch_id == "0"


def test_decompile_main(session):
    oracle, client = session
    model, markup = decompile(oracle, client, "main")
    assert model is not None and markup is not None
    assert model.attr("name") == "main"
    ast = model.first("ast")
    assert ast is not None and len(ast.find("block")) >= 3
    text = render_c(markup)
    assert "authenticate" in text
    assert "if" in text and "else" in text


def test_decompile_authenticate(session):
    oracle, client = session
    model, markup = decompile(oracle, client, "authenticate")
    text = render_c(markup)
    assert "accepted" not in text  # authenticate doesn't call accepted
    assert model.first("prototype") is not None
