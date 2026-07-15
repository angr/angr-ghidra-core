"""Convenience session wrapper: spin up a core (real or angr), register a program
from a binary via PypcodeOracle, and decompile functions by name/address.
"""

from __future__ import annotations

from ..ghidra_wire import PackedEncoder, ids
from ..ghidra_wire.clang import render_c, split_decompile_response
from ..ghidra_wire.client import DecompClient
from ..ghidra_wire.dump import parse_tree
from .oracle import SPACE_RAM, PypcodeOracle

REAL_CORE = "/workspace/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/ghidra_opt"
ANGR_CORE = ["/workspace/angr-venv/bin/python", "/workspace/angr-ghidra-core/bin/angr-decompile"]


class DecompSession:
    def __init__(self, binary: str, core=REAL_CORE, trace=None, **oracle_kw):
        self.oracle = PypcodeOracle(binary, trace=trace, **oracle_kw)
        self.client = DecompClient(core, self.oracle, trace=trace)
        self.client.register_program(
            self.oracle.pspec(), self.oracle.cspec(), self.oracle.tspec(),
            self.oracle.coretypes(),
        )
        self.client.set_action("decompile", "")
        self.client.set_action("", "tree")
        self.client.set_action("", "c")

    def function(self, name: str):
        return next(f for f in self.oracle.functions.values() if f.name == name)

    def decompile(self, name_or_addr):
        if isinstance(name_or_addr, str):
            addr = self.function(name_or_addr).addr
        else:
            addr = name_or_addr
        enc = PackedEncoder()
        enc.open_element(ids.ELEM_ADDR)
        enc.write_space(ids.ATTRIB_SPACE, SPACE_RAM)
        enc.write_unsigned(ids.ATTRIB_OFFSET, addr)
        enc.close_element(ids.ELEM_ADDR)
        result = self.client.decompile_at(enc)
        if not result:
            raise RuntimeError(f"empty response (error: {self.client.error_message})")
        roots = parse_tree(result)
        model, markup = split_decompile_response(roots)
        return DecompResult(result, roots, model, markup)

    def close(self):
        self.client.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class DecompResult:
    def __init__(self, raw, roots, model, markup):
        self.raw = raw
        self.roots = roots
        self.model = model
        self.markup = markup

    @property
    def c(self) -> str:
        return render_c(self.markup) if self.markup is not None else ""

    @property
    def high_function(self):
        from ..ghidra_wire.highfunc import decode_high_function
        return decode_high_function(self.model) if self.model is not None else None

    @property
    def token_symrefs(self):
        from ..ghidra_wire.highfunc import collect_token_symrefs
        return collect_token_symrefs(self.markup) if self.markup is not None else []
