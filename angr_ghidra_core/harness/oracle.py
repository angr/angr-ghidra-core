"""A program oracle that plays Ghidra's role in the decompiler protocol.

Backs the callback queries (getBytes, getPcode, getRegister, getMappedSymbols, ...)
with CLE (binary loading) and pypcode (SLEIGH lifting), and authors the four
registerProgram spec documents. Used to drive either the real C++ core or the
angr-backed core without a Ghidra installation.
"""

from __future__ import annotations

import html
from pathlib import Path

import cle
import pypcode

from ..ghidra_wire import ids
from ..ghidra_wire.address import Addr, decode_addr, decode_addr_in_element
from ..ghidra_wire.packed import PackedDecoder, PackedEncoder

# Address space indices for the tspec we author.
# Index 0 is the constant space (created implicitly by the core);
# the OTHER space is required by the core to be index 1.
SPACE_CONST = 0
SPACE_OTHER = 1
SPACE_RAM = 2
SPACE_REGISTER = 3
SPACE_UNIQUE = 4

SPACE_INDEX_BY_NAME = {
    "const": SPACE_CONST,
    "OTHER": SPACE_OTHER,
    "ram": SPACE_RAM,
    "register": SPACE_REGISTER,
    "unique": SPACE_UNIQUE,
}

UNIQUE_BASE = 0x10000000  # decompiler-allocated uniques start here, above SLEIGH's

CORE_TYPES = [
    # (name, size, metatype, is_char)
    ("void", 1, "void", False),
    ("bool", 1, "bool", False),
    ("uint", 4, "uint", False),
    ("byte", 1, "uint", False),
    ("ushort", 2, "uint", False),
    ("ulong", 8, "uint", False),
    ("int", 4, "int", False),
    ("char", 1, "int", True),
    ("sbyte", 1, "int", False),
    ("short", 2, "int", False),
    ("long", 8, "int", False),
    ("float", 4, "float", False),
    ("double", 8, "float", False),
    ("float10", 10, "float", False),
    ("float16", 16, "float", False),
    ("undefined1", 1, "unknown", False),
    ("undefined2", 2, "unknown", False),
    ("undefined3", 3, "unknown", False),
    ("undefined4", 4, "unknown", False),
    ("undefined5", 5, "unknown", False),
    ("undefined6", 6, "unknown", False),
    ("undefined7", 7, "unknown", False),
    ("undefined8", 8, "unknown", False),
    ("code", 1, "code", False),
    ("wchar_t", 4, "int", True),
    ("wchar16", 2, "int", True),
    ("xunknown1", 1, "unknown", False),  # placeholder to keep ids stable
]

BUILTIN_ID_HEADER = 0xC000000000000000

GLOBAL_NAMESPACE_ID = 0


class Function:
    def __init__(self, addr: int, name: str, size: int, symbol_id: int):
        self.addr = addr
        self.name = name
        self.size = size
        self.symbol_id = symbol_id


class PypcodeOracle:
    """Oracle over a single loaded binary."""

    def __init__(
        self,
        binary_path: str,
        langid: str | None = None,
        pspec: str | None = None,
        cspec: str | None = None,
        ghidra_root: str = "/workspace/ghidra",
        trace=None,
    ):
        self.binary_path = binary_path
        self.loader = cle.Loader(binary_path, auto_load_libs=False)

        # derive the Ghidra language + spec documents from the loaded arch, so
        # the oracle stands in for Ghidra on any supported architecture. Explicit
        # langid/pspec/cspec still win (e.g. x86-64 default paths below).
        from .archmap import spec_for_arch
        archspec = spec_for_arch(self.loader.main_object.arch)
        if langid is None:
            langid = archspec.langid if archspec else "x86:LE:64:default"
        self._archspec = archspec

        self.ctx = pypcode.Context(langid)
        self.langid = langid
        self.ghidra_root = Path(ghidra_root)
        self.trace = trace or (lambda *a: None)

        self._pspec_path = pspec or (archspec.pspec_path if archspec else None)
        self._cspec_path = cspec or (archspec.cspec_path if archspec else None)
        self._ptr_bytes = archspec.ptr_bytes if archspec else 8
        self._bigendian = archspec.bigendian if archspec else False

        # register maps
        self.reg_by_name: dict[str, tuple[int, int]] = {}
        for name, vn in self.ctx.registers.items():
            self.reg_by_name[name] = (vn.offset, vn.size)
        self.reg_by_loc: dict[tuple[int, int], str] = {}
        for name, (off, size) in self.reg_by_name.items():
            # prefer the shortest canonical name for a location
            key = (off, size)
            cur = self.reg_by_loc.get(key)
            if cur is None or len(name) < len(cur):
                self.reg_by_loc[key] = name

        # core type ids
        self.coretype_ids = {
            name: BUILTIN_ID_HEADER | (i + 0x10) for i, (name, _, _, _) in enumerate(CORE_TYPES)
        }

        # the integer return register for this arch (from the compiler spec),
        # used as the unlocked return-storage hint in function prototypes
        ret_name = archspec.return_register if archspec else "RAX"
        self.return_register = self.reg_by_name.get(ret_name) \
            or self.reg_by_name.get(ret_name.upper()) \
            or self.reg_by_name.get("RAX", (0, self._ptr_bytes))

        # functions from the binary's symbol table
        self.functions: dict[int, Function] = {}
        next_id = 0x10000
        mo = self.loader.main_object
        for sym in mo.symbols:
            if sym.is_function and sym.rebased_addr and sym.size:
                self.functions[sym.rebased_addr] = Function(
                    sym.rebased_addr, sym.name, sym.size, next_id
                )
                next_id += 1

        # a broader address->name map for label queries: real functions, PLT
        # stubs (imports), and any named symbol. Mirrors what Ghidra's symbol
        # table would answer for getCodeLabel / getMappedSymbols.
        self.labels: dict[int, str] = {f.addr: f.name for f in self.functions.values()}
        for addr, name in getattr(mo, "reverse_plt", {}).items():
            self.labels.setdefault(addr, name)
        for sym in mo.symbols:
            if sym.name and sym.rebased_addr:
                self.labels.setdefault(sym.rebased_addr, sym.name)

        # Thumb ranges: on ARM, CLE marks a Thumb function with an odd symbol
        # address. Real Ghidra tracks the T-mode context register and lifts
        # p-code in the right mode; we emulate that for getPcode by setting the
        # SLEIGH TMode context variable over these ranges, so the core's Thumb
        # probe (getPcode instruction length) sees the true 2-byte instructions.
        self._is_arm = mo.arch.name.upper().startswith("ARM")
        self._thumb_ranges: list[tuple[int, int]] = []
        if self._is_arm:
            for f in self.functions.values():
                if f.addr & 1:
                    base = f.addr & ~1
                    self._thumb_ranges.append((base, base + f.size))

    def _addr_is_thumb(self, addr: int) -> bool:
        return any(lo <= addr < hi for lo, hi in self._thumb_ranges)

    def add_function(self, addr: int, name: str, size: int) -> None:
        self.functions[addr] = Function(addr, name, size, 0x10000 + len(self.functions))

    def function_containing(self, addr: int) -> Function | None:
        for f in self.functions.values():
            if f.addr <= addr < f.addr + f.size:
                return f
        return None

    # ------------------------------------------------------------ specs

    def pspec(self) -> str:
        if self._pspec_path:
            return Path(self._pspec_path).read_text()
        # default: x86-64
        return (
            self.ghidra_root
            / "Ghidra/Processors/x86/data/languages/x86-64.pspec"
        ).read_text()

    def cspec(self) -> str:
        if self._cspec_path:
            return Path(self._cspec_path).read_text()
        return (
            self.ghidra_root
            / "Ghidra/Processors/x86/data/languages/x86-64-gcc.cspec"
        ).read_text()

    def tspec(self, bigendian: bool | None = None) -> str:
        # endianness and pointer width come from the loaded arch (a 32-bit arch
        # has a 4-byte ram address size); the register space stays 4 bytes.
        if bigendian is None:
            bigendian = self._bigendian
        be = "true" if bigendian else "false"
        ram_size = self._ptr_bytes
        return (
            f'<sleigh bigendian="{be}" uniqbase="0x{UNIQUE_BASE:x}">\n'
            "  <spaces defaultspace=\"ram\">\n"
            f'    <space_other name="OTHER" index="{SPACE_OTHER}" size="{ram_size}" bigendian="{be}"'
            ' delay="0" physical="true"/>\n'
            f'    <space name="ram" index="{SPACE_RAM}" size="{ram_size}" bigendian="{be}"'
            ' delay="1" physical="true"/>\n'
            f'    <space name="register" index="{SPACE_REGISTER}" size="4" bigendian="{be}"'
            ' delay="0" physical="true"/>\n'
            f'    <space_unique name="unique" index="{SPACE_UNIQUE}" size="4" bigendian="{be}"'
            ' delay="0" physical="true"/>\n'
            "  </spaces>\n"
            "</sleigh>\n"
        )

    def coretypes(self) -> str:
        lines = ["<coretypes>"]
        for name, size, metatype, is_char in CORE_TYPES:
            tid = self.coretype_ids[name]
            extra = ' char="true"' if is_char else ""
            lines.append(
                f'  <type name="{html.escape(name)}" size="{size}" metatype="{metatype}"'
                f'{extra} id="0x{tid:x}"/>'
            )
        lines.append("</coretypes>")
        return "\n".join(lines)

    # ------------------------------------------------- encoding helpers

    def _encode_typeref(self, enc: PackedEncoder, name: str) -> None:
        enc.open_element(ids.ELEM_TYPEREF)
        enc.write_string(ids.ATTRIB_NAME, name)
        enc.write_unsigned(ids.ATTRIB_ID, self.coretype_ids[name])
        enc.close_element(ids.ELEM_TYPEREF)

    def _encode_void_addr(self, enc: PackedEncoder) -> None:
        enc.open_element(ids.ELEM_ADDR)
        enc.close_element(ids.ELEM_ADDR)

    def _encode_function_symbol(self, enc: PackedEncoder, func: Function) -> None:
        """encodeResult(HighFunctionSymbol) equivalent: <doc id><mapsym>...</mapsym></doc>."""
        enc.open_element(ids.ELEM_DOC)
        enc.write_unsigned(ids.ATTRIB_ID, GLOBAL_NAMESPACE_ID)
        enc.open_element(ids.ELEM_MAPSYM)

        # HighFunction.encode: the <function> element
        enc.open_element(ids.ELEM_FUNCTION)
        enc.write_unsigned(ids.ATTRIB_ID, func.symbol_id)
        enc.write_string(ids.ATTRIB_NAME, func.name)
        enc.write_signed(ids.ATTRIB_SIZE, max(func.size, 1))
        enc.open_element(ids.ELEM_ADDR)
        enc.write_space(ids.ATTRIB_SPACE, SPACE_RAM)
        enc.write_unsigned(ids.ATTRIB_OFFSET, func.addr)
        enc.close_element(ids.ELEM_ADDR)

        # <localdb lock=false main=stack><scope name>...
        enc.open_element(ids.ELEM_LOCALDB)
        enc.write_bool(ids.ATTRIB_LOCK, False)
        enc.write_special_space(ids.ATTRIB_MAIN, 0)  # stack
        enc.open_element(ids.ELEM_SCOPE)
        enc.write_string(ids.ATTRIB_NAME, func.name)
        enc.open_element(ids.ELEM_PARENT)
        enc.write_unsigned(ids.ATTRIB_ID, GLOBAL_NAMESPACE_ID)
        enc.close_element(ids.ELEM_PARENT)
        enc.open_element(ids.ELEM_RANGELIST)
        enc.close_element(ids.ELEM_RANGELIST)
        enc.open_element(ids.ELEM_SYMBOLLIST)
        enc.close_element(ids.ELEM_SYMBOLLIST)
        enc.close_element(ids.ELEM_SCOPE)
        enc.close_element(ids.ELEM_LOCALDB)

        # <prototype extrapop="unknown" model="unknown"><returnsym>...
        enc.open_element(ids.ELEM_PROTOTYPE)
        enc.write_string(ids.ATTRIB_EXTRAPOP, "unknown")
        enc.write_string(ids.ATTRIB_MODEL, "unknown")
        enc.open_element(ids.ELEM_RETURNSYM)
        # Unlocked return hint: undefined8 in the conventional return register
        # (Ghidra's DB assigns default-convention storage even for signature-less
        # functions; an empty <addr/> with a non-void type is rejected by the core).
        ret_off, ret_size = self.return_register
        enc.open_element(ids.ELEM_ADDR)
        enc.write_space(ids.ATTRIB_SPACE, SPACE_REGISTER)
        enc.write_unsigned(ids.ATTRIB_OFFSET, ret_off)
        enc.write_signed(ids.ATTRIB_SIZE, ret_size)
        enc.close_element(ids.ELEM_ADDR)
        self._encode_typeref(enc, "undefined8")
        enc.close_element(ids.ELEM_RETURNSYM)
        enc.close_element(ids.ELEM_PROTOTYPE)
        enc.close_element(ids.ELEM_FUNCTION)

        # MappedEntry: storage varnode + empty rangelist
        enc.open_element(ids.ELEM_ADDR)
        enc.write_space(ids.ATTRIB_SPACE, SPACE_RAM)
        enc.write_unsigned(ids.ATTRIB_OFFSET, func.addr)
        enc.write_signed(ids.ATTRIB_SIZE, max(func.size, 1))
        enc.close_element(ids.ELEM_ADDR)
        enc.open_element(ids.ELEM_RANGELIST)
        enc.close_element(ids.ELEM_RANGELIST)

        enc.close_element(ids.ELEM_MAPSYM)
        enc.close_element(ids.ELEM_DOC)

    def _encode_hole(self, enc: PackedEncoder, space: int, first: int, last: int,
                     readonly: bool = False) -> None:
        enc.open_element(ids.ELEM_HOLE)
        if readonly:
            enc.write_bool(ids.ATTRIB_READONLY, True)
        enc.write_space(ids.ATTRIB_SPACE, space)
        enc.write_unsigned(ids.ATTRIB_FIRST, first)
        enc.write_unsigned(ids.ATTRIB_LAST, last)
        enc.close_element(ids.ELEM_HOLE)

    # ------------------------------------------------------ query handlers

    def query_getbytes(self, dec: PackedDecoder):
        el = dec.open_element(ids.ELEM_ADDR)
        addr = decode_addr_in_element(dec)
        size = dec.read_attribute(ids.ATTRIB_SIZE)
        dec.close_element_skipping(el)
        self.trace("oracle", "getbytes", (addr, size))
        if addr.space != SPACE_RAM:
            return None
        data = self.loader.memory.load(addr.offset, size)
        return bytes(data)

    def query_getpcode(self, dec: PackedDecoder):
        addr, _ = decode_addr(dec)
        self.trace("oracle", "getpcode", addr)
        enc = PackedEncoder()
        try:
            code = bytes(self.loader.memory.load(addr.offset, 16))
        except KeyError:
            return enc  # empty -> BadDataError in the core
        # decode in the right ARM mode (Thumb inside a Thumb function), mirroring
        # Ghidra's per-address T-mode tracking
        if self._is_arm:
            self.ctx.setVariableDefault("TMode", 1 if self._addr_is_thumb(addr.offset) else 0)
        try:
            tx = self.ctx.translate(code, base_address=addr.offset, max_instructions=1)
            ops = tx.ops
        except Exception:
            return enc
        if not ops or ops[0].opcode != pypcode.OpCode.IMARK:
            return enc
        length = sum(vn.size for vn in ops[0].inputs)
        real_ops = [op for op in ops if op.opcode != pypcode.OpCode.IMARK]

        # pypcode raises at translate time for unimplemented instructions
        # (handled above as an empty reply -> BadDataError in the core)
        enc.open_element(ids.ELEM_INST)
        enc.write_signed(ids.ATTRIB_OFFSET, length)
        enc.open_element(ids.ELEM_ADDR)
        enc.write_space(ids.ATTRIB_SPACE, SPACE_RAM)
        enc.write_unsigned(ids.ATTRIB_OFFSET, addr.offset)
        enc.close_element(ids.ELEM_ADDR)
        for op in real_ops:
            self._encode_op(enc, op)
        enc.close_element(ids.ELEM_INST)
        return enc

    def _encode_varnode(self, enc: PackedEncoder, vn) -> None:
        enc.open_element(ids.ELEM_ADDR)
        enc.write_space(ids.ATTRIB_SPACE, SPACE_INDEX_BY_NAME[vn.space.name])
        enc.write_unsigned(ids.ATTRIB_OFFSET, vn.offset)
        enc.write_signed(ids.ATTRIB_SIZE, vn.size)
        enc.close_element(ids.ELEM_ADDR)

    def _encode_op(self, enc: PackedEncoder, op) -> None:
        opcode = op.opcode.value
        enc.open_element(ids.ELEM_OP)
        enc.write_opcode(ids.ATTRIB_CODE, opcode)
        enc.write_signed(ids.ATTRIB_SIZE, len(op.inputs))
        if op.output is None:
            enc.open_element(ids.ELEM_VOID)
            enc.close_element(ids.ELEM_VOID)
        else:
            self._encode_varnode(enc, op.output)
        inputs = op.inputs
        if op.opcode in (pypcode.OpCode.LOAD, pypcode.OpCode.STORE):
            space = inputs[0].getSpaceFromConst()
            enc.open_element(ids.ELEM_SPACEID)
            enc.write_space(ids.ATTRIB_NAME, SPACE_INDEX_BY_NAME[space.name])
            enc.close_element(ids.ELEM_SPACEID)
            rest = inputs[1:]
        else:
            rest = inputs
        for vn in rest:
            self._encode_varnode(enc, vn)
        enc.close_element(ids.ELEM_OP)

    def query_getregister(self, dec: PackedDecoder):
        name = dec.read_attribute(ids.ATTRIB_NAME)
        self.trace("oracle", "getregister", name)
        if name not in self.reg_by_name:
            raise RuntimeError(f"No Register Defined: {name}")
        offset, size = self.reg_by_name[name]
        enc = PackedEncoder()
        enc.open_element(ids.ELEM_ADDR)
        enc.write_space(ids.ATTRIB_SPACE, SPACE_REGISTER)
        enc.write_unsigned(ids.ATTRIB_OFFSET, offset)
        enc.write_signed(ids.ATTRIB_SIZE, size)
        enc.close_element(ids.ELEM_ADDR)
        return enc

    def query_getregistername(self, dec: PackedDecoder):
        el = dec.open_element(ids.ELEM_ADDR)
        addr = decode_addr_in_element(dec)
        size = dec.read_attribute(ids.ATTRIB_SIZE)
        dec.close_element_skipping(el)
        name = self.reg_by_loc.get((addr.offset, size), "")
        self.trace("oracle", "getregistername", (addr, size, name))
        return name

    def query_gettrackedregisters(self, dec: PackedDecoder):
        addr, _ = decode_addr(dec)
        self.trace("oracle", "gettrackedregisters", addr)
        enc = PackedEncoder()
        enc.open_element(ids.ELEM_TRACKED_POINTSET)
        enc.write_space(ids.ATTRIB_SPACE, addr.space if isinstance(addr.space, int) else SPACE_RAM)
        enc.write_unsigned(ids.ATTRIB_OFFSET, addr.offset)
        enc.close_element(ids.ELEM_TRACKED_POINTSET)
        return enc

    def query_getuseropname(self, dec: PackedDecoder):
        index = dec.read_attribute(ids.ATTRIB_INDEX)
        name = self.ctx.language.get_userop_name(index) if hasattr(
            self.ctx.language, "get_userop_name") else None
        self.trace("oracle", "getuseropname", (index, name))
        return name or ""

    def query_getmappedsymbols(self, dec: PackedDecoder):
        addr, _ = decode_addr(dec)
        self.trace("oracle", "getmappedsymbols", addr)
        enc = PackedEncoder()
        if addr.space != SPACE_RAM:
            self._encode_hole(enc, addr.space if isinstance(addr.space, int) else SPACE_RAM,
                              addr.offset, addr.offset)
            return enc
        func = self.function_containing(addr.offset)
        if func is not None:
            if addr.offset == func.addr:
                self._encode_function_symbol(enc, func)
            else:
                # off-cut query inside a function body: hole to end of function
                self._encode_hole(enc, SPACE_RAM, addr.offset, func.addr + func.size - 1,
                                  readonly=True)
            return enc
        self._encode_hole(enc, SPACE_RAM, addr.offset, addr.offset)
        return enc

    def query_getexternalref(self, dec: PackedDecoder):
        addr, _ = decode_addr(dec)
        self.trace("oracle", "getexternalref", addr)
        func = self.functions.get(addr.offset)
        if func is None:
            return None
        enc = PackedEncoder()
        self._encode_function_symbol(enc, func)
        return enc

    def query_getnamespacepath(self, dec: PackedDecoder):
        nsid = dec.read_attribute(ids.ATTRIB_ID)
        self.trace("oracle", "getnamespacepath", nsid)
        enc = PackedEncoder()
        enc.open_element(ids.ELEM_PARENT)
        enc.open_element(ids.ELEM_VAL)
        enc.close_element(ids.ELEM_VAL)
        enc.close_element(ids.ELEM_PARENT)
        return enc

    def query_getcomments(self, dec: PackedDecoder):
        _types = dec.read_attribute(ids.ATTRIB_TYPE)
        addr, _ = decode_addr(dec)
        self.trace("oracle", "getcomments", addr)
        enc = PackedEncoder()
        enc.open_element(ids.ELEM_COMMENTDB)
        enc.close_element(ids.ELEM_COMMENTDB)
        return enc

    def query_getcodelabel(self, dec: PackedDecoder):
        addr, _ = decode_addr(dec)
        name = self.labels.get(addr.offset, "")
        self.trace("oracle", "getcodelabel", (addr, name))
        return name

    def query_getdatatype(self, dec: PackedDecoder):
        name = dec.read_attribute(ids.ATTRIB_NAME)
        self.trace("oracle", "getdatatype", name)
        return None  # only core types exist in this oracle

    def query_isnameused(self, dec: PackedDecoder):
        return False

    def query_getstringdata(self, dec: PackedDecoder):
        return None

    def query_getcpoolref(self, dec: PackedDecoder):
        return None

    def query_getcallfixup(self, dec: PackedDecoder):
        return None

    def query_getcallmech(self, dec: PackedDecoder):
        return None

    def query_getcallotherfixup(self, dec: PackedDecoder):
        return None

    def query_getpcodeexecutable(self, dec: PackedDecoder):
        return None
