"""Emit a decompileAt <doc> response from an angr decompilation result:
a minimal-but-valid model <function> plus the Clang C-markup token tree.
"""

from __future__ import annotations

from ..ghidra_wire import ids
from ..ghidra_wire.packed import PackedEncoder

# Ghidra ClangToken color constants (ClangToken.java:34-44)
KEYWORD_COLOR = 0
COMMENT_COLOR = 1
TYPE_COLOR = 2
FUNCTION_COLOR = 3
VARIABLE_COLOR = 4
CONST_COLOR = 5
GLOBAL_COLOR = 7
DEFAULT_COLOR = 8



def _color_for(obj) -> int | None:
    """Pick a token color from the angr C-AST node type of a chunk, or None to
    skip emitting (whitespace-only chunks with no node)."""
    if obj is None:
        return None
    cls = type(obj).__name__
    if cls in ("CFunction", "CFunctionCall"):
        return FUNCTION_COLOR
    if cls == "CVariable":
        return VARIABLE_COLOR
    if cls == "CConstant":
        return CONST_COLOR
    if cls.startswith("SimType"):
        return TYPE_COLOR
    if cls == "CStructField":
        return VARIABLE_COLOR
    return None


class ResponseEmitter:
    def __init__(self, space_ram: int, space_register: int, return_register: tuple[int, int],
                 coretype_ids: dict):
        self.space_ram = space_ram
        self.space_register = space_register
        self.return_register = return_register
        self.coretype_ids = coretype_ids

    def emit_doc(self, name: str, entry: int, size: int, codegen, var_table=None) -> bytes:
        enc = PackedEncoder()
        enc.open_element(ids.ELEM_DOC)
        self._emit_model_function(enc, name, entry, size, var_table)
        self._emit_markup_function(enc, codegen, var_table)
        enc.close_element(ids.ELEM_DOC)
        return enc.to_bytes()

    def _typeref(self, enc: PackedEncoder, name: str) -> None:
        enc.open_element(ids.ELEM_TYPEREF)
        enc.write_string(ids.ATTRIB_NAME, name)
        tid = self.coretype_ids.get(name)
        if tid is not None:
            enc.write_unsigned(ids.ATTRIB_ID, tid)
        enc.close_element(ids.ELEM_TYPEREF)

    # ---- model <function> (HighFunction.decode-compatible, no ast/highlist) ----

    def _emit_model_function(self, enc: PackedEncoder, name: str, entry: int, size: int,
                             var_table) -> None:
        enc.open_element(ids.ELEM_FUNCTION)
        enc.write_string(ids.ATTRIB_NAME, name)
        enc.write_signed(ids.ATTRIB_SIZE, max(size, 1))
        enc.open_element(ids.ELEM_ADDR)
        enc.write_space(ids.ATTRIB_SPACE, self.space_ram)
        enc.write_unsigned(ids.ATTRIB_OFFSET, entry)
        enc.close_element(ids.ELEM_ADDR)

        enc.open_element(ids.ELEM_LOCALDB)
        enc.write_bool(ids.ATTRIB_LOCK, False)
        enc.write_special_space(ids.ATTRIB_MAIN, 0)  # stack
        enc.open_element(ids.ELEM_SCOPE)
        enc.write_string(ids.ATTRIB_NAME, name)
        enc.open_element(ids.ELEM_PARENT)
        enc.write_unsigned(ids.ATTRIB_ID, 0)
        enc.close_element(ids.ELEM_PARENT)
        enc.open_element(ids.ELEM_RANGELIST)
        enc.close_element(ids.ELEM_RANGELIST)
        enc.open_element(ids.ELEM_SYMBOLLIST)
        if var_table is not None:
            for sym in var_table.symbols:
                self._emit_mapsym(enc, sym)
        enc.close_element(ids.ELEM_SYMBOLLIST)
        enc.close_element(ids.ELEM_SCOPE)
        enc.close_element(ids.ELEM_LOCALDB)

        enc.open_element(ids.ELEM_PROTOTYPE)
        enc.write_string(ids.ATTRIB_EXTRAPOP, "unknown")
        enc.write_string(ids.ATTRIB_MODEL, "unknown")
        enc.open_element(ids.ELEM_RETURNSYM)
        off, sz = self.return_register
        enc.open_element(ids.ELEM_ADDR)
        enc.write_space(ids.ATTRIB_SPACE, self.space_register)
        enc.write_unsigned(ids.ATTRIB_OFFSET, off)
        enc.write_signed(ids.ATTRIB_SIZE, sz)
        enc.close_element(ids.ELEM_ADDR)
        self._typeref(enc, "undefined8")
        enc.close_element(ids.ELEM_RETURNSYM)
        enc.close_element(ids.ELEM_PROTOTYPE)
        enc.close_element(ids.ELEM_FUNCTION)

    def _emit_mapsym(self, enc: PackedEncoder, sym) -> None:
        """One <mapsym>: the <symbol> header+type, then a MappedEntry <addr>/rangelist."""
        enc.open_element(ids.ELEM_MAPSYM)
        enc.open_element(ids.ELEM_SYMBOL)
        enc.write_unsigned(ids.ATTRIB_ID, sym.sym_id)
        enc.write_string(ids.ATTRIB_NAME, sym.name)
        enc.write_bool(ids.ATTRIB_TYPELOCK, False)
        enc.write_bool(ids.ATTRIB_NAMELOCK, False)
        enc.write_signed(ids.ATTRIB_CAT, sym.category)
        if sym.cat_index >= 0:
            enc.write_unsigned(ids.ATTRIB_INDEX, sym.cat_index)
        self._typeref(enc, sym.type_name)
        enc.close_element(ids.ELEM_SYMBOL)

        # MappedEntry: <addr storage><rangelist/>
        enc.open_element(ids.ELEM_ADDR)
        if sym.storage_kind == "stack":
            enc.write_special_space(ids.ATTRIB_SPACE, 0)  # stack special space
        else:
            enc.write_space(ids.ATTRIB_SPACE, sym.space)
        enc.write_unsigned(ids.ATTRIB_OFFSET, sym.offset & 0xFFFFFFFFFFFFFFFF)
        enc.write_signed(ids.ATTRIB_SIZE, sym.size)
        enc.close_element(ids.ELEM_ADDR)
        enc.open_element(ids.ELEM_RANGELIST)
        enc.close_element(ids.ELEM_RANGELIST)
        enc.close_element(ids.ELEM_MAPSYM)

    # ---- markup <function>: the Clang token tree ----

    def _emit_markup_function(self, enc: PackedEncoder, codegen, var_table) -> None:
        enc.open_element(ids.ELEM_FUNCTION)
        # flatten the codegen chunk stream into syntax/variable/type/... tokens,
        # turning embedded newlines into <break> elements with indentation.
        for text, obj in codegen.cfunc.c_repr_chunks(indent=0):
            if not text:
                continue
            color = _color_for(obj)
            symref = None
            if type(obj).__name__ == "CVariable" and var_table is not None:
                symref = var_table.symref_for(obj.variable)
            segments = text.split("\n")
            for i, seg in enumerate(segments):
                if i > 0:
                    stripped = seg.lstrip(" ")
                    indent = len(seg) - len(stripped)
                    enc.open_element(ids.ELEM_BREAK)
                    enc.write_signed(ids.ATTRIB_INDENT, indent)
                    enc.close_element(ids.ELEM_BREAK)
                    seg = stripped
                if not seg:
                    continue
                self._emit_token(enc, seg, color, symref)
        enc.close_element(ids.ELEM_FUNCTION)

    def _emit_token(self, enc: PackedEncoder, text: str, color: int | None,
                    symref: int | None = None) -> None:
        if color == VARIABLE_COLOR:
            enc.open_element(ids.ELEM_VARIABLE)
            enc.write_signed(ids.ATTRIB_COLOR, color)
            if symref is not None:
                enc.write_unsigned(ids.ATTRIB_SYMREF, symref)
            enc.write_string(ids.ATTRIB_CONTENT, text)
            enc.close_element(ids.ELEM_VARIABLE)
        elif color == FUNCTION_COLOR:
            enc.open_element(ids.ELEM_FUNCNAME)
            enc.write_signed(ids.ATTRIB_COLOR, color)
            enc.write_string(ids.ATTRIB_CONTENT, text)
            enc.close_element(ids.ELEM_FUNCNAME)
        elif color == TYPE_COLOR:
            enc.open_element(ids.ELEM_TYPE)
            enc.write_signed(ids.ATTRIB_COLOR, color)
            enc.write_string(ids.ATTRIB_CONTENT, text)
            enc.close_element(ids.ELEM_TYPE)
        elif color is None:
            enc.open_element(ids.ELEM_SYNTAX)
            enc.write_string(ids.ATTRIB_CONTENT, text)
            enc.close_element(ids.ELEM_SYNTAX)
        else:  # constants and anything else -> syntax token with a color
            enc.open_element(ids.ELEM_SYNTAX)
            enc.write_signed(ids.ATTRIB_COLOR, color)
            enc.write_string(ids.ATTRIB_CONTENT, text)
            enc.close_element(ids.ELEM_SYNTAX)
