"""Drive the real C++ decompiler core (ghidra_opt) with our Python harness:
register a program, decompile a function, dump the response tree.

Usage: python scripts/drive_real_core.py [binary] [function_name] [--trace]
"""

from __future__ import annotations

import sys

from angr_ghidra_core.ghidra_wire import PackedEncoder, ids
from angr_ghidra_core.ghidra_wire.client import DecompClient
from angr_ghidra_core.ghidra_wire.dump import parse_tree
from angr_ghidra_core.harness.oracle import SPACE_RAM, PypcodeOracle

CORE = "/workspace/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/ghidra_opt"


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    binary = args[0] if args else "/workspace/binaries/tests/x86_64/fauxware"
    funcname = args[1] if len(args) > 1 else "main"
    do_trace = "--trace" in sys.argv

    trace = (lambda who, kind, what: print(f"[{who}] {kind}: {what}", file=sys.stderr)) \
        if do_trace else None

    oracle = PypcodeOracle(binary, trace=trace)
    func = next(f for f in oracle.functions.values() if f.name == funcname)
    print(f"target: {func.name} @ {func.addr:#x} size {func.size}", file=sys.stderr)

    client = DecompClient(CORE, oracle, trace=trace)
    try:
        arch_id = client.register_program(
            oracle.pspec(), oracle.cspec(), oracle.tspec(), oracle.coretypes()
        )
        print(f"registered, archId={arch_id!r} err={client.error_message!r}", file=sys.stderr)
        if not arch_id:
            print(client.proc.stderr.read(4096).decode(errors="replace"), file=sys.stderr)
            return

        ok = client.set_action("decompile", "")
        print(f"setAction decompile -> {ok}", file=sys.stderr)
        ok = client.set_action("", "tree")
        print(f"setAction tree -> {ok}", file=sys.stderr)
        ok = client.set_action("", "c")
        print(f"setAction c -> {ok}", file=sys.stderr)

        enc = PackedEncoder()
        enc.open_element(ids.ELEM_ADDR)
        enc.write_space(ids.ATTRIB_SPACE, SPACE_RAM)
        enc.write_unsigned(ids.ATTRIB_OFFSET, func.addr)
        enc.close_element(ids.ELEM_ADDR)
        result = client.decompile_at(enc)
        print(f"response: {len(result)} bytes", file=sys.stderr)
        if client.error_message:
            print(f"core error: {client.error_message}", file=sys.stderr)
        if result:
            roots = parse_tree(result)
            if "--dump" in sys.argv:
                for root in roots:
                    print(root.pretty(max_depth=3))
            from angr_ghidra_core.ghidra_wire.clang import render_c, split_decompile_response

            model, markup = split_decompile_response(roots)
            print(f"model: {'yes' if model else 'no'}, markup: {'yes' if markup else 'no'}",
                  file=sys.stderr)
            if markup is not None:
                print(render_c(markup))
    finally:
        client.close()


if __name__ == "__main__":
    main()
