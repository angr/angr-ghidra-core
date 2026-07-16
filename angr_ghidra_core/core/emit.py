"""Emit a decompileAt <doc> response from an angr decompilation result:
a minimal-but-valid model <function> plus the Clang C-markup token tree.
"""

from __future__ import annotations

import re

from ..ghidra_wire import ids
from ..ghidra_wire.packed import PackedEncoder

# split a type name into identifier runs vs everything else (spaces, '*', ...)
_TYPE_SPLIT = re.compile(r"[A-Za-z0-9_]+|[^A-Za-z0-9_]+")

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
                 coretype_ids: dict, space_unique: int = 4):
        self.space_ram = space_ram
        self.space_register = space_register
        self.space_unique = space_unique
        self.return_register = return_register
        self.coretype_ids = coretype_ids
        self.space_const = 0  # ConstantSpace is always index 0

    def emit_doc(self, name: str, entry: int, size: int, codegen, var_table=None,
                 translator=None) -> bytes:
        enc = PackedEncoder()
        enc.open_element(ids.ELEM_DOC)
        self._emit_model_function(enc, name, entry, size, var_table, translator)
        self._emit_markup_function(enc, codegen, var_table)
        enc.close_element(ids.ELEM_DOC)
        return enc.to_bytes()

    def emit_parammeasures(self, name: str, entry: int, inputs, output) -> bytes:
        """Response for the paramid action: recovered parameters/return so Ghidra
        can populate the function signature. `inputs` is a list of (space, offset,
        size, type_name); `output` is one such tuple or None."""
        enc = PackedEncoder()
        enc.open_element(ids.ELEM_DOC)
        enc.open_element(ids.ELEM_PARAMMEASURES)
        enc.write_string(ids.ATTRIB_NAME, name)
        enc.open_element(ids.ELEM_ADDR)
        enc.write_space(ids.ATTRIB_SPACE, self.space_ram)
        enc.write_unsigned(ids.ATTRIB_OFFSET, entry)
        enc.close_element(ids.ELEM_ADDR)
        enc.open_element(ids.ELEM_PROTO)
        enc.write_string(ids.ATTRIB_MODEL, "unknown")
        enc.write_string(ids.ATTRIB_EXTRAPOP, "unknown")
        enc.close_element(ids.ELEM_PROTO)
        for rank, (space, offset, size, type_name) in enumerate(inputs):
            self._emit_parammeasure(enc, ids.ELEM_INPUT, space, offset, size, type_name, rank)
        if output is not None:
            space, offset, size, type_name = output
            self._emit_parammeasure(enc, ids.ELEM_OUTPUT, space, offset, size, type_name, 0)
        enc.close_element(ids.ELEM_PARAMMEASURES)
        enc.close_element(ids.ELEM_DOC)
        return enc.to_bytes()

    def _emit_parammeasure(self, enc, elem, space, offset, size, type_name, rank):
        # ParamMeasure.decode: varnode, then datatype, then <rank val>
        enc.open_element(elem)
        enc.open_element(ids.ELEM_ADDR)
        if isinstance(space, str) and space == "stack":
            enc.write_special_space(ids.ATTRIB_SPACE, 0)
        else:
            enc.write_space(ids.ATTRIB_SPACE, space)
        enc.write_unsigned(ids.ATTRIB_OFFSET, offset & 0xFFFFFFFFFFFFFFFF)
        enc.write_signed(ids.ATTRIB_SIZE, size)
        enc.close_element(ids.ELEM_ADDR)
        self._typeref(enc, type_name)
        enc.open_element(ids.ELEM_RANK)
        enc.write_signed(ids.ATTRIB_VAL, rank)
        enc.close_element(ids.ELEM_RANK)
        enc.close_element(elem)

    def _typeref(self, enc: PackedEncoder, name: str) -> None:
        # a typeref must resolve against the registered core types; if the name
        # isn't present, fall back to one that is (undefined8, then any).
        if name not in self.coretype_ids:
            if "undefined8" in self.coretype_ids:
                name = "undefined8"
            elif self.coretype_ids:
                name = next(iter(self.coretype_ids))
        enc.open_element(ids.ELEM_TYPEREF)
        enc.write_string(ids.ATTRIB_NAME, name)
        tid = self.coretype_ids.get(name)
        if tid is not None:
            enc.write_unsigned(ids.ATTRIB_ID, tid)
        enc.close_element(ids.ELEM_TYPEREF)

    # ---- model <function> (HighFunction.decode-compatible, no ast/highlist) ----

    def _emit_model_function(self, enc: PackedEncoder, name: str, entry: int, size: int,
                             var_table, translator=None) -> None:
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
        enc.write_unsigned(ids.ATTRIB_ID, 1)  # function scope id (non-global)
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

        # <ast> registers a representative varnode per variable (markup tokens
        # reference these by create-index via varref); <highlist> groups them
        # into HighVariables linked to their symbols. Both must come after
        # <localdb> (highlist resolves symrefs against the LocalSymbolMap) and
        # the varnodes must be registered before the highlist references them.
        if var_table is not None and var_table.symbols:
            self._emit_ast(enc, var_table, translator)
            self._emit_highlist(enc, var_table)

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

    def _emit_var_storage_addr(self, enc: PackedEncoder, sym, ref: int | None = None,
                               addrtied: bool = False) -> None:
        """Encode a <addr> for a variable's storage, optionally with a varnode ref."""
        enc.open_element(ids.ELEM_ADDR)
        if ref is not None:
            enc.write_unsigned(ids.ATTRIB_REF, ref)
        if sym.storage_kind == "stack":
            enc.write_special_space(ids.ATTRIB_SPACE, 0)  # stack special space
        else:
            enc.write_space(ids.ATTRIB_SPACE, sym.space)
        enc.write_unsigned(ids.ATTRIB_OFFSET, sym.offset & 0xFFFFFFFFFFFFFFFF)
        enc.write_signed(ids.ATTRIB_SIZE, sym.size)
        # An addr-tied representative makes Ghidra store the variable (and any
        # rename/retype) at its fixed address rather than a DynamicHash -- which
        # would need the full p-code op graph to round-trip. Stack locals live at
        # a fixed slot, so this is accurate.
        if addrtied and sym.storage_kind == "stack":
            enc.write_bool(ids.ATTRIB_ADDRTIED, True)
        enc.close_element(ids.ELEM_ADDR)

    def _emit_ast(self, enc: PackedEncoder, var_table, translator=None) -> None:
        """The <ast>: all varnodes, then basic blocks with their p-code ops, then
        block edges. Without a translator, falls back to a blockless AST of just
        the representative varnodes (PcodeSyntaxTree.decode accepts that)."""
        if translator is None:
            enc.open_element(ids.ELEM_AST)
            enc.open_element(ids.ELEM_VARNODES)
            for sym in var_table.symbols:
                self._emit_var_storage_addr(enc, sym, ref=sym.varnode_ref, addrtied=True)
            enc.close_element(ids.ELEM_VARNODES)
            enc.close_element(ids.ELEM_AST)
            return

        stack_reps = {s.offset for s in var_table.symbols if s.storage_kind == "stack"}
        enc.open_element(ids.ELEM_AST)
        enc.open_element(ids.ELEM_VARNODES)
        for vn in translator.varnodes:
            self._emit_pcode_varnode(enc, vn, addrtied=(vn.space == "stack"
                                                        and vn.offset in stack_reps))
        enc.close_element(ids.ELEM_VARNODES)
        for blk in translator.blocks:
            self._emit_block(enc, blk, translator)
        for blk in translator.blocks:
            if blk.in_edges:
                enc.open_element(ids.ELEM_BLOCKEDGE)
                enc.write_signed(ids.ATTRIB_INDEX, blk.index)
                for src_index, rev in blk.in_edges:
                    enc.open_element(ids.ELEM_EDGE)
                    enc.write_signed(ids.ATTRIB_END, src_index)
                    enc.write_signed(ids.ATTRIB_REV, rev)
                    enc.close_element(ids.ELEM_EDGE)
                enc.close_element(ids.ELEM_BLOCKEDGE)
        enc.close_element(ids.ELEM_AST)

    def _emit_pcode_varnode(self, enc, vn, ref=None, addrtied=False) -> None:
        enc.open_element(ids.ELEM_ADDR)
        enc.write_unsigned(ids.ATTRIB_REF, vn.ref if ref is None else ref)
        if vn.space == "const":
            enc.write_space(ids.ATTRIB_SPACE, self.space_const)
        elif vn.space == "stack":
            enc.write_special_space(ids.ATTRIB_SPACE, 0)
        elif vn.space == "register":
            enc.write_space(ids.ATTRIB_SPACE, self.space_register)
        else:  # unique
            enc.write_space(ids.ATTRIB_SPACE, self.space_unique)
        enc.write_unsigned(ids.ATTRIB_OFFSET, vn.offset & 0xFFFFFFFFFFFFFFFF)
        enc.write_signed(ids.ATTRIB_SIZE, vn.size)
        if addrtied:
            enc.write_bool(ids.ATTRIB_ADDRTIED, True)
        enc.close_element(ids.ELEM_ADDR)

    def _emit_block(self, enc, blk, translator) -> None:
        enc.open_element(ids.ELEM_BLOCK)
        enc.write_signed(ids.ATTRIB_INDEX, blk.index)
        enc.open_element(ids.ELEM_RANGELIST)
        enc.open_element(ids.ELEM_RANGE)
        enc.write_space(ids.ATTRIB_SPACE, self.space_ram)
        enc.write_unsigned(ids.ATTRIB_FIRST, blk.addr)
        enc.write_unsigned(ids.ATTRIB_LAST, blk.addr_last)
        enc.close_element(ids.ELEM_RANGE)
        enc.close_element(ids.ELEM_RANGELIST)
        for op in translator.ops_by_block(blk):
            self._emit_pcode_op(enc, op)
        enc.close_element(ids.ELEM_BLOCK)

    def _emit_pcode_op(self, enc, op) -> None:
        enc.open_element(ids.ELEM_OP)
        enc.write_opcode(ids.ATTRIB_CODE, op.opcode)
        enc.open_element(ids.ELEM_SEQNUM)
        enc.write_unsigned(ids.ATTRIB_UNIQ, op.time)
        enc.write_space(ids.ATTRIB_SPACE, self.space_ram)
        enc.write_unsigned(ids.ATTRIB_OFFSET, op.ins_addr)
        enc.close_element(ids.ELEM_SEQNUM)
        if op.output is None:
            enc.open_element(ids.ELEM_VOID)
            enc.close_element(ids.ELEM_VOID)
        else:
            enc.open_element(ids.ELEM_ADDR)
            enc.write_unsigned(ids.ATTRIB_REF, op.output)
            enc.close_element(ids.ELEM_ADDR)
        for ref in op.inputs:
            enc.open_element(ids.ELEM_ADDR)
            enc.write_unsigned(ids.ATTRIB_REF, ref)
            enc.close_element(ids.ELEM_ADDR)
        enc.close_element(ids.ELEM_OP)

    def _emit_highlist(self, enc: PackedEncoder, var_table) -> None:
        """One <high> per variable (HighLocal / HighParam): symref links to the
        LocalSymbolMap symbol, repref + a member varnode reference the AST
        varnode, so token varrefs resolve to a HighVariable."""
        enc.open_element(ids.ELEM_HIGHLIST)
        for sym in var_table.symbols:
            enc.open_element(ids.ELEM_HIGH)
            enc.write_string(ids.ATTRIB_CLASS, sym.high_class)  # 'l' or 'p'
            enc.write_unsigned(ids.ATTRIB_SYMREF, sym.sym_id)
            enc.write_unsigned(ids.ATTRIB_REPREF, sym.varnode_ref)
            # datatype (decodeInstances reads it right after repref)
            self._typeref(enc, sym.type_name)
            # member varnode(s): reference the representative by ref
            enc.open_element(ids.ELEM_ADDR)
            enc.write_unsigned(ids.ATTRIB_REF, sym.varnode_ref)
            enc.close_element(ids.ELEM_ADDR)
            enc.close_element(ids.ELEM_HIGH)
        enc.close_element(ids.ELEM_HIGHLIST)

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
        self._emit_var_storage_addr(enc, sym)
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
            varref = None
            if type(obj).__name__ == "CVariable" and var_table is not None:
                sym = var_table.by_var_id.get(id(obj.variable))
                if sym is not None:
                    varref = sym.varnode_ref
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
                self._emit_token(enc, seg, color, varref)
        enc.close_element(ids.ELEM_FUNCTION)

    def _emit_type_token(self, enc: PackedEncoder, text: str) -> None:
        # Ghidra runs ClangTypeToken content through IllegalCharCppTransformer,
        # which replaces spaces / '*' with '_' (its own type names are single
        # words, so it never hits this; angr's are multi-word, e.g. "unsigned
        # long long"). Emit identifier runs as <type> tokens (colored, and left
        # unchanged since they have no illegal chars) and the separators between
        # them as plain <syntax> tokens, which the transformer never touches.
        for part in _TYPE_SPLIT.findall(text):
            if part[0].isalnum() or part[0] == "_":
                enc.open_element(ids.ELEM_TYPE)
                enc.write_unsigned(ids.ATTRIB_COLOR, TYPE_COLOR)
                enc.write_string(ids.ATTRIB_CONTENT, part)
                enc.close_element(ids.ELEM_TYPE)
            else:
                enc.open_element(ids.ELEM_SYNTAX)
                enc.write_string(ids.ATTRIB_CONTENT, part)
                enc.close_element(ids.ELEM_SYNTAX)

    def _emit_token(self, enc: PackedEncoder, text: str, color: int | None,
                    varref: int | None = None) -> None:
        if color == VARIABLE_COLOR:
            enc.open_element(ids.ELEM_VARIABLE)
            enc.write_unsigned(ids.ATTRIB_COLOR, color)
            if varref is not None:
                enc.write_unsigned(ids.ATTRIB_VARREF, varref)
            enc.write_string(ids.ATTRIB_CONTENT, text)
            enc.close_element(ids.ELEM_VARIABLE)
        elif color == FUNCTION_COLOR:
            enc.open_element(ids.ELEM_FUNCNAME)
            enc.write_unsigned(ids.ATTRIB_COLOR, color)
            enc.write_string(ids.ATTRIB_CONTENT, text)
            enc.close_element(ids.ELEM_FUNCNAME)
        elif color == TYPE_COLOR:
            self._emit_type_token(enc, text)
        elif color is None:
            enc.open_element(ids.ELEM_SYNTAX)
            enc.write_string(ids.ATTRIB_CONTENT, text)
            enc.close_element(ids.ELEM_SYNTAX)
        else:  # constants and anything else -> syntax token with a color
            enc.open_element(ids.ELEM_SYNTAX)
            enc.write_unsigned(ids.ATTRIB_COLOR, color)
            enc.write_string(ids.ATTRIB_CONTENT, text)
            enc.close_element(ids.ELEM_SYNTAX)
