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
from .edits import apply_user_edits, parse_user_edits
from .emit import ResponseEmitter
from .prototypes import (
    prototype_from_ghidra,
    prototype_from_libraries,
    set_stub_prototype,
)
from .spec import SpecInfo, parse_specs
from .variables import VariableSymbolTable

log = logging.getLogger("angr_ghidra_core")

WINDOW_PAD = 0x40  # bytes fetched before/after the function body for CFG context


def clean_symbol_name(name: str) -> str:
    """Strip Ghidra's getCodeLabel namespace prefix. getSymbolName prefixes a
    label with its namespace path ("<ns>_<ns>_..._name"), so external functions
    come back as "<EXTERNAL>_atoi" (and library-nested ones as
    "<EXTERNAL>_libc.so.6_atoi"). Drop each leading angle-bracketed namespace
    segment, returning the base name ("atoi")."""
    while name and name.startswith("<") and ">_" in name:
        name = name.split(">_", 1)[1]
    return name


class AngrCore:
    def __init__(self, transport: ServerTransport):
        self.t = transport
        self.spec: SpecInfo | None = None
        self.arch_id = 0
        self.action = "decompile"
        self._project_cache: dict = {}
        self._proto_cache: dict = {}  # callee addr -> recovered prototype (or None)

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
        self._proto_cache.clear()
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
        fn_el = self._query_mapped_function(entry)
        name = (fn_el.attr("name") if fn_el is not None else None) or f"func_{entry:x}"
        # NOTE: the getMappedSymbols size is the symbol's storage size (e.g. a
        # pointer width), NOT the function's code length -- the real core never
        # needs the length because it follows p-code flow. So fetch a generous
        # readable window and let angr's CFG find the function's real extent.
        code = self._fetch_window(entry)

        # The paramid action asks only for the recovered parameters/return, so
        # Ghidra can populate the function signature (its own decompiler does
        # this too). Returning them here is what makes *calls* to local functions
        # show arguments on later decompiles.
        if self.action == "paramid":
            return self._paramid(entry, name, code)

        codegen, arch, func_size = self._decompile(entry, name, code)
        # honour user edits (renames/retypes) committed to Ghidra's DB: they come
        # back in the localdb as locked symbols; apply them to angr's variables.
        self._apply_user_edits(codegen, fn_el, arch)
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
        fn = self._query_mapped_function(entry)
        if fn is None:
            return f"func_{entry:x}", None
        return fn.attr("name", f"func_{entry:x}"), fn.attr("size")

    def _query_mapped_function(self, entry: int):
        """Return the model <function> Element from getMappedSymbols, or None."""
        enc = PackedEncoder()
        enc.open_element(ids.ELEM_COMMAND_GETMAPPEDSYMBOLS)
        encode_addr(enc, Addr(self.spec.space_ram, entry))
        enc.close_element(ids.ELEM_COMMAND_GETMAPPEDSYMBOLS)
        kind, payload = self.t.query(enc)
        if kind != "string" or not payload:
            return None
        for root in parse_tree(payload):
            for mapsym in root.find("mapsym"):
                fn = mapsym.first("function")
                if fn is not None:
                    if os.environ.get("ANGR_GHIDRA_DEBUG"):
                        log.error("mapped %#x proto:\n%s", entry, fn.pretty(max_depth=6))
                    return fn
        return None

    def _query_register_name(self, offset: int, size: int) -> str | None:
        enc = PackedEncoder()
        enc.open_element(ids.ELEM_COMMAND_GETREGISTERNAME)
        enc.open_element(ids.ELEM_ADDR)
        enc.write_space(ids.ATTRIB_SPACE, self.spec.space_register)
        enc.write_unsigned(ids.ATTRIB_OFFSET, offset)
        enc.write_signed(ids.ATTRIB_SIZE, size)
        enc.close_element(ids.ELEM_ADDR)
        enc.close_element(ids.ELEM_COMMAND_GETREGISTERNAME)
        kind, payload = self.t.query(enc)
        if kind == "string" and payload:
            return payload.decode("utf-8")
        return None

    def _apply_user_edits(self, codegen, fn_el, arch) -> None:
        edits = parse_user_edits(fn_el)
        if not edits:
            return

        def reg_to_angr(offset, size):
            try:
                nm = self._query_register_name(offset, size)
                if nm:
                    return arch.registers[nm.lower()]
            except Exception:
                return None
            return None

        def set_type(uv, type_el):
            return False  # retype handled in the type-mapping step

        try:
            apply_user_edits(codegen, edits, self.spec.space_register, reg_to_angr, set_type)
        except Exception:
            log.exception("apply_user_edits failed")

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

    def _load_and_cfg(self, entry: int, name: str, code: bytes, function_starts=None):
        import angr

        proj = angr.load_shellcode(
            code,
            arch=self.spec.angr_arch,
            start_offset=0,
            load_address=entry,
            support_selfmodifying_code=False,
        )
        # extra function starts bound the CFG so a small callee doesn't fall
        # through into an adjacent function (which corrupts CC recovery)
        starts = {entry}
        if function_starts:
            starts.update(function_starts)
        cfg = proj.analyses.CFGFast(
            normalize=True,
            regions=[(entry, entry + len(code))],
            function_starts=list(starts),
            start_at_entry=False,
            force_complete_scan=False,
        )
        func = cfg.functions.get(entry)
        if func is None:
            func = proj.kb.functions.function(addr=entry, create=True)
        func.name = name
        return proj, cfg, func

    def _decompile(self, entry: int, name: str, code: bytes):
        proj, cfg, func = self._load_and_cfg(entry, name, code)
        self._name_call_targets(proj, func, entry, len(code))
        dec = proj.analyses.Decompiler(func, cfg=cfg.model)
        if dec.codegen is None:
            raise RuntimeError(f"angr produced no code for {name} @ {entry:#x}")
        func_size = func.size or len(code)
        return dec.codegen, proj.arch, func_size

    def _paramid(self, entry: int, name: str, code: bytes) -> bytes:
        """Recover the function's parameters/return with angr and emit them as a
        <parammeasures> response (the paramid action)."""
        inputs, output = [], None
        try:
            proj, cfg, func = self._load_and_cfg(entry, name, code)
            proj.analyses.VariableRecoveryFast(func)
            cca = proj.analyses.CallingConvention(func, cfg=cfg.model, analyze_callsites=True)
            cc, proto = cca.cc, cca.prototype
        except Exception:
            cc = proto = None
        if cc is not None and proto is not None:
            for ty, loc in zip(proto.args, cc.arg_locs(proto)):
                slot = self._arg_slot(loc)
                if slot is not None:
                    inputs.append(slot)
            if proto.returnty is not None:
                try:
                    rloc = cc.return_val(proto.returnty)
                except Exception:
                    rloc = None
                rslot = self._arg_slot(rloc) if rloc is not None else None
                if rslot is not None:
                    output = rslot
        if os.environ.get("ANGR_GHIDRA_DEBUG"):
            log.error("paramid %s @ %#x: cc=%s inputs=%s output=%s",
                      name, entry, cc, inputs, output)
        return self.emitter.emit_parammeasures(name, entry, inputs, output)

    def _arg_slot(self, loc):
        """Map an angr argument location to (space, offset, size, type_name)."""
        cls = type(loc).__name__
        size = getattr(loc, "size", 8) or 8
        type_name = f"undefined{size}" if 1 <= size <= 8 else "undefined8"
        if cls == "SimRegArg":
            try:
                off, rsize = self._query_register(loc.reg_name.upper())
            except Exception:
                return None
            return (self.spec.space_register, off, rsize, type_name)
        if cls == "SimStackArg":
            return ("stack", getattr(loc, "stack_offset", 0), size, type_name)
        return None

    def _name_call_targets(self, proj, func, entry: int, size: int) -> None:
        """For each call target, create a named, returning function stub in angr's
        KB and give it the callee's prototype, so calls render with names AND
        arguments. Targets lie outside the scoped blob, so the CFG doesn't
        register them itself; we scan the function's call instructions. Name and
        prototype both come from one getMappedSymbols query per target."""
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
            fn_el = None
            try:
                fn_el = self._query_mapped_function(tgt)
            except Exception:
                fn_el = None
            name = self._target_name(tgt, fn_el)
            stub = proj.kb.functions.function(addr=tgt, name=name, create=True)
            # external stubs have no body; assume they return so the decompiler
            # emits normal call statements (not "/* do not return */")
            stub.returning = True
            # give the stub the callee's prototype so angr recovers call args.
            # entry + sibling call targets bound each callee's own recovery.
            try:
                proto = self._callee_prototype(tgt, fn_el, name, proj.arch, {entry, *targets})
                if proto is not None:
                    set_stub_prototype(stub, proto, proj.arch)
            except Exception:
                pass

    def _callee_prototype(self, tgt: int, fn_el, name: str, arch, known_starts):
        """Best prototype for a call target: an authoritative Ghidra signature if
        it has parameters (libc, user-edited), else a library prototype by name,
        else one recovered by analysing the callee ourselves (local functions
        whose params Ghidra hasn't recovered)."""
        if fn_el is not None:
            gproto = prototype_from_ghidra(fn_el, arch)
            if gproto is not None and gproto.args:
                return gproto
        libproto = prototype_from_libraries(name)
        if libproto is not None:
            return libproto
        recovered = self._recover_callee_prototype(tgt, known_starts)
        if recovered is not None:
            return recovered
        # last resort: Ghidra's (0-arg) prototype, if any
        return prototype_from_ghidra(fn_el, arch) if fn_el is not None else None

    def _recover_callee_prototype(self, tgt: int, known_starts):
        """Analyse a local callee with angr to recover its prototype. Cached per
        process (cleared by flushNative); None is cached too, to avoid retrying.
        known_starts bounds the callee so it doesn't merge with a neighbour."""
        if tgt in self._proto_cache:
            return self._proto_cache[tgt]
        proto = None
        try:
            code = self._fetch_window(tgt)
            proj, cfg, func = self._load_and_cfg(tgt, f"sub_{tgt:x}", code, known_starts)
            proj.analyses.VariableRecoveryFast(func)
            cca = proj.analyses.CallingConvention(func, cfg=cfg.model, analyze_callsites=True)
            if cca.cc is not None and cca.prototype is not None:
                proto = cca.prototype
        except Exception:
            proto = None
        self._proto_cache[tgt] = proto
        return proto

    def _target_name(self, tgt: int, fn_el) -> str:
        """Clean base name for a call target, from the mapped function or, failing
        that, getCodeLabel (namespace prefix stripped)."""
        if fn_el is not None:
            mapped = fn_el.attr("name")
            if mapped and not mapped.startswith("func_"):
                return clean_symbol_name(mapped)
        try:
            label = clean_symbol_name(self._query_code_label(tgt))
        except Exception:
            label = None
        return label or f"sub_{tgt:x}"


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
