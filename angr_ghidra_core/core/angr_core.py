"""angr-backed decompiler core: the server counterpart to Ghidra's C++ `decompile`.

Reads commands over stdin, loads the target function's bytes through the getBytes
callback (Ghidra as the oracle), runs the angr Decompiler on a scoped CFG, and
returns a decompileAt <doc> response.
"""

from __future__ import annotations

import os
import io
import logging
import sys
import traceback

from ..ghidra_wire import ids
from ..ghidra_wire.address import Addr, encode_addr
from ..ghidra_wire.dump import parse_tree
from ..ghidra_wire.packed import PackedDecoder, PackedEncoder
from ..ghidra_wire.server import ServerTransport
from .emit import ResponseEmitter
from .spec import SpecInfo, parse_specs
from .variables import VariableSymbolTable

log = logging.getLogger("angr_ghidra_core")

WINDOW_PAD = 0x40  # bytes fetched before/after the function body for CFG context


class AngrCore:
    def __init__(self, transport: ServerTransport):
        self.t = transport
        self.spec: SpecInfo | None = None
        self.arch_id = 0
        self.action = "decompile"
        self._project_cache: dict = {}

    # ------------------------------------------------------------- main loop

    def serve(self) -> None:
        while True:
            try:
                name, params = self.t.read_command()
            except EOFError:
                return
            handler = getattr(self, "cmd_" + name, None)
            # response-start is written before the body so callback queries the
            # body issues are seen inside Ghidra's response-reading loop
            self.t.begin_response()
            payload, error = None, ""
            if handler is None:
                error = f"Low-level Error: Bad command {name}"
            else:
                try:
                    payload = handler(params)
                except SystemExit:
                    self.t.end_response(payload, error)
                    return
                except Exception as e:  # never die on one bad command
                    log.exception("command %s failed", name)
                    error = f"Low-level Error: {e}"
                    log.debug("%s", traceback.format_exc())
            self.t.end_response(payload, error)

    # ------------------------------------------------------------- commands

    def cmd_registerProgram(self, params: list[bytes]) -> str:
        pspec, cspec, tspec, coretypes = (p.decode("utf-8") for p in params[:4])
        dump = os.environ.get("ANGR_DUMP_SPECS")
        if dump:
            for nm, txt in (("pspec", pspec), ("cspec", cspec), ("tspec", tspec),
                            ("coretypes", coretypes)):
                with open(f"{dump}.{nm}", "w") as fh:
                    fh.write(txt)
        self.spec = parse_specs(pspec, cspec, tspec, coretypes)
        self.emitter = None
        return str(self.arch_id)

    def _ensure_emitter(self) -> None:
        if self.emitter is not None:
            return
        # resolve the return register storage via a getRegister callback, so the
        # offset matches Ghidra's register-space convention exactly
        off, size = self._query_register(self.spec.return_register_name)
        self.emitter = ResponseEmitter(
            self.spec.space_ram, self.spec.space_register, (off, size),
            self.spec.coretype_ids,
        )

    def cmd_deregisterProgram(self, params: list[bytes]):
        # terminate after this response is written (SystemExit handled in serve)
        self._pending_exit = True
        raise SystemExit(0)

    def cmd_flushNative(self, params: list[bytes]) -> str:
        self._project_cache.clear()
        return "1"

    def cmd_setAction(self, params: list[bytes]) -> str:
        # params: archId, actionstring, printstring
        if len(params) >= 2 and params[1]:
            self.action = params[1].decode("utf-8")
        return "t"

    def cmd_setOptions(self, params: list[bytes]) -> str:
        return "t"

    def cmd_decompileAt(self, params: list[bytes]) -> bytes:
        # params: archId, <packed addr>
        dec = PackedDecoder(params[1])
        el = dec.open_element(ids.ELEM_ADDR)
        attrs = dict(dec.attributes())
        entry = attrs.get(ids.ATTRIB_OFFSET, 0)
        dec.close_element_skipping(el)

        self._ensure_emitter()
        name, _size = self._query_function(entry)
        # NOTE: the getMappedSymbols size is the symbol's storage size (e.g. a
        # pointer width), NOT the function's code length -- the real core never
        # needs the length because it follows p-code flow. So fetch a generous
        # readable window and let angr's CFG find the function's real extent.
        code = self._fetch_window(entry)
        codegen, arch, func_size = self._decompile(entry, name, code)
        var_table = VariableSymbolTable(self._query_register, self.spec.space_register)
        var_table.build(codegen, arch)
        doc = self.emitter.emit_doc(name, entry, func_size, codegen, var_table)
        dump = os.environ.get("ANGR_DUMP_RESPONSE")
        if dump:
            with open(dump, "wb") as fh:
                fh.write(doc)
        return doc

    # ------------------------------------------------------- Ghidra queries

    def _query_register(self, name: str) -> tuple[int, int]:
        enc = PackedEncoder()
        enc.open_element(ids.ELEM_COMMAND_GETREGISTER)
        enc.write_string(ids.ATTRIB_NAME, name)
        enc.close_element(ids.ELEM_COMMAND_GETREGISTER)
        kind, payload = self.t.query(enc)
        if kind != "string" or not payload:
            return (0, 8)
        dec = PackedDecoder(payload)
        dec.open_element(ids.ELEM_ADDR)
        attrs = dict(dec.attributes())
        return attrs.get(ids.ATTRIB_OFFSET, 0), attrs.get(ids.ATTRIB_SIZE, 8)

    def _query_function(self, entry: int) -> tuple[str, int | None]:
        enc = PackedEncoder()
        enc.open_element(ids.ELEM_COMMAND_GETMAPPEDSYMBOLS)
        encode_addr(enc, Addr(self.spec.space_ram, entry))
        enc.close_element(ids.ELEM_COMMAND_GETMAPPEDSYMBOLS)
        kind, payload = self.t.query(enc)
        if kind != "string" or not payload:
            return f"func_{entry:x}", None
        roots = parse_tree(payload)
        # <doc><mapsym><function name size>...
        for root in roots:
            for mapsym in root.find("mapsym"):
                fn = mapsym.first("function")
                if fn is not None:
                    return fn.attr("name", f"func_{entry:x}"), fn.attr("size")
        return f"func_{entry:x}", None

    def _query_code_label(self, addr: int) -> str:
        enc = PackedEncoder()
        enc.open_element(ids.ELEM_COMMAND_GETCODELABEL)
        encode_addr(enc, Addr(self.spec.space_ram, addr))
        enc.close_element(ids.ELEM_COMMAND_GETCODELABEL)
        kind, payload = self.t.query(enc)
        if kind == "string" and payload:
            return payload.decode("utf-8")
        return ""

    WINDOW = 0x2000       # max bytes to pull for one function
    CHUNK = 0x100         # granularity for probing readable extent

    def _get_bytes(self, addr: int, size: int) -> bytes | None:
        """One getBytes callback. Ghidra returns null (empty) if any byte in the
        range is unreadable."""
        enc = PackedEncoder()
        enc.open_element(ids.ELEM_COMMAND_GETBYTES)
        enc.open_element(ids.ELEM_ADDR)
        enc.write_space(ids.ATTRIB_SPACE, self.spec.space_ram)
        enc.write_unsigned(ids.ATTRIB_OFFSET, addr)
        enc.write_signed(ids.ATTRIB_SIZE, size)
        enc.close_element(ids.ELEM_ADDR)
        enc.close_element(ids.ELEM_COMMAND_GETBYTES)
        kind, payload = self.t.query(enc)
        if kind != "bytes" or not payload:
            return None
        return payload

    def _fetch_window(self, entry: int) -> bytes:
        """Fetch a readable window starting at entry, chunk by chunk, stopping at
        the first unreadable chunk (Ghidra fails the whole range if any byte is
        unmapped). Returns at least one chunk or raises."""
        out = bytearray()
        addr = entry
        while len(out) < self.WINDOW:
            chunk = self._get_bytes(addr, self.CHUNK)
            if chunk is None:
                break
            out.extend(chunk)
            addr += len(chunk)
            if len(chunk) < self.CHUNK:
                break
        if not out:
            # last resort: try successively smaller reads at the entry
            for sz in (0x80, 0x40, 0x10, 0x8, 0x1):
                chunk = self._get_bytes(entry, sz)
                if chunk:
                    return bytes(chunk)
            raise RuntimeError(f"getBytes returned no data at {entry:#x}")
        return bytes(out)

    # ------------------------------------------------------------ angr run

    def _decompile(self, entry: int, name: str, code: bytes):
        import angr

        proj = angr.load_shellcode(
            code,
            arch=self.spec.angr_arch,
            start_offset=0,
            load_address=entry,
            support_selfmodifying_code=False,
        )
        cfg = proj.analyses.CFGFast(
            normalize=True,
            regions=[(entry, entry + len(code))],
            function_starts=[entry],
            start_at_entry=False,
            force_complete_scan=False,
        )
        func = cfg.functions.get(entry)
        if func is None:
            func = proj.kb.functions.function(addr=entry, create=True)
        func.name = name
        self._name_call_targets(proj, func, entry, len(code))
        dec = proj.analyses.Decompiler(func, cfg=cfg.model)
        if dec.codegen is None:
            raise RuntimeError(f"angr produced no code for {name} @ {entry:#x}")
        func_size = func.size or len(code)
        return dec.codegen, proj.arch, func_size

    def _name_call_targets(self, proj, func, entry: int, size: int) -> None:
        """Resolve each call target's name from Ghidra (getCodeLabel) and create a
        named, returning function stub in angr's KB so calls render with names
        instead of raw addresses. Targets are found by scanning the function's
        call instructions (they lie outside the scoped blob, so the CFG doesn't
        register them itself)."""
        targets: set[int] = set()
        for block in func.blocks:
            try:
                insns = block.capstone.insns
            except Exception:
                continue
            for ins in insns:
                if ins.mnemonic == "call":
                    try:
                        targets.add(int(ins.op_str, 16))
                    except ValueError:
                        pass  # indirect call
        for tgt in targets:
            if tgt == entry:
                continue
            try:
                label = self._query_code_label(tgt)
            except Exception:
                label = ""
            name = label or f"sub_{tgt:x}"
            stub = proj.kb.functions.function(addr=tgt, name=name, create=True)
            # external stubs have no body; assume they return so the decompiler
            # emits normal call statements (not "/* do not return */")
            stub.returning = True


def main() -> None:
    logging.basicConfig(
        level=logging.WARNING, stream=sys.stderr, format="[angr-core] %(message)s"
    )
    logging.getLogger("angr").setLevel(logging.ERROR)
    logging.getLogger("cle").setLevel(logging.ERROR)
    stdin = sys.stdin.buffer if hasattr(sys.stdin, "buffer") else sys.stdin
    stdout = sys.stdout.buffer if hasattr(sys.stdout, "buffer") else sys.stdout
    transport = ServerTransport(stdin, stdout)
    AngrCore(transport).serve()


if __name__ == "__main__":
    main()
