"""Translate angr's AIL graph into a Ghidra p-code op graph.

Ghidra's HighFunction model is a p-code SSA syntax tree: varnodes defined and used
by ops, grouped into basic blocks with control-flow edges. angr decompiles via
AIL (VEX-derived), not p-code, so we lower AIL blocks/statements/expressions into
p-code triples: each AIL VirtualVariable becomes a varnode, each statement one or
more ops, nested expressions are flattened through temporary (unique-space)
varnodes. The result gives Ghidra a real def-use graph (p-code graph views,
variable def/use highlighting).

This is a best-effort lowering: it preserves data-flow shape (who defines/uses
what) rather than exact instruction semantics, and falls back to undefined
temporaries for expression forms it doesn't model.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# p-code opcodes (values match pypcode/Ghidra)
COPY = 1
LOAD = 2
STORE = 3
BRANCH = 4
CBRANCH = 5
BRANCHIND = 6
CALL = 7
CALLIND = 8
RETURN = 10
INT_EQUAL = 11
INT_NOTEQUAL = 12
INT_SLESS = 13
INT_LESS = 15
INT_ZEXT = 17
INT_SEXT = 18
INT_ADD = 19
INT_SUB = 20
INT_2COMP = 24
INT_NEGATE = 25
INT_XOR = 26
INT_AND = 27
INT_OR = 28
INT_LEFT = 29
INT_RIGHT = 30
INT_SRIGHT = 31
INT_MULT = 32
BOOL_NEGATE = 37
BOOL_AND = 39
BOOL_OR = 40
PIECE = 62
SUBPIECE = 63

# space kinds used by a varnode
SPACE_CONST = "const"
SPACE_STACK = "stack"
SPACE_REGISTER = "register"
SPACE_UNIQUE = "unique"

# AIL binary-op name -> p-code opcode
_BINOP = {
    "Add": INT_ADD, "Sub": INT_SUB, "Mul": INT_MULT,
    "And": INT_AND, "Or": INT_OR, "Xor": INT_XOR,
    "Shl": INT_LEFT, "Shr": INT_RIGHT, "Sar": INT_SRIGHT,
    "CmpEQ": INT_EQUAL, "CmpNE": INT_NOTEQUAL,
    "CmpLT": INT_LESS, "CmpLE": INT_LESS, "CmpGT": INT_LESS, "CmpGE": INT_LESS,
    "CmpLTs": INT_SLESS, "CmpLEs": INT_SLESS, "CmpGTs": INT_SLESS, "CmpGEs": INT_SLESS,
    "LogicalAnd": BOOL_AND, "LogicalOr": BOOL_OR,
}


@dataclass
class Varnode:
    ref: int
    space: str          # SPACE_* kind
    offset: int         # value (const), stack offset, register offset, or unique id
    size: int


@dataclass
class Op:
    opcode: int
    ins_addr: int
    time: int
    output: int | None      # varnode ref, or None
    inputs: list[int]       # varnode refs
    space_input: str | None = None  # for LOAD/STORE: the referenced space kind


@dataclass
class Block:
    index: int
    addr: int
    addr_last: int
    op_times: list[int] = field(default_factory=list)
    in_edges: list[tuple[int, int]] = field(default_factory=list)  # (src_index, rev_index)


class PcodeTranslator:
    def __init__(self, reg_offset_lookup):
        """reg_offset_lookup(vex_reg_offset, size) -> Ghidra register-space offset,
        or None."""
        self._reg_lookup = reg_offset_lookup
        self.varnodes: list[Varnode] = []
        self.ops: list[Op] = []
        self.blocks: list[Block] = []
        self._vvar_ref: dict[int, int] = {}     # varid -> varnode ref
        self._by_ref: dict[int, Varnode] = {}    # varnode ref -> Varnode
        self._stack_rep: dict[int, int] = {}     # stack offset -> representative ref
        self._reg_rep: dict[int, int] = {}       # ghidra reg offset -> representative ref
        self._stack_members: dict[int, list[int]] = {}  # stack offset -> all refs there
        self._reg_members: dict[int, list[int]] = {}    # ghidra reg offset -> all refs
        self._next_ref = 0x300                   # varnode create-index namespace
        self._next_time = 1
        self._next_unique = 0x10000000

    # ------------------------------------------------------------ varnodes

    def _new_varnode(self, space, offset, size) -> int:
        ref = self._next_ref
        self._next_ref += 1
        vn = Varnode(ref, space, offset, size)
        self.varnodes.append(vn)
        self._by_ref[ref] = vn
        return ref

    def _const(self, value, size) -> int:
        return self._new_varnode(SPACE_CONST, value & ((1 << 64) - 1), max(size, 1))

    def _temp(self, size) -> int:
        off = self._next_unique
        self._next_unique += max(size, 1)
        return self._new_varnode(SPACE_UNIQUE, off, max(size, 1))

    def _vvar(self, vvar) -> int:
        vid = vvar.varid
        if vid in self._vvar_ref:
            return self._vvar_ref[vid]
        size = max(vvar.size or 1, 1)
        if vvar.was_stack:
            ref = self._new_varnode(SPACE_STACK, vvar.stack_offset, size)
            self._stack_rep.setdefault(vvar.stack_offset, ref)
            self._stack_members.setdefault(vvar.stack_offset, []).append(ref)
        elif vvar.was_reg or _is_register(vvar):
            reg_off = _reg_offset(vvar)
            g_off = self._reg_lookup(reg_off, size) if reg_off is not None else None
            if g_off is None:
                ref = self._temp(size)
            else:
                ref = self._new_varnode(SPACE_REGISTER, g_off, size)
                self._reg_rep.setdefault(g_off, ref)
                self._reg_members.setdefault(g_off, []).append(ref)
        else:
            ref = self._temp(size)
        self._vvar_ref[vid] = ref
        return ref

    # representative varnode refs for wiring HighVariables into the op graph
    def stack_representative(self, offset: int) -> int | None:
        return self._stack_rep.get(offset)

    def register_representative(self, g_offset: int) -> int | None:
        return self._reg_rep.get(g_offset)

    def variable_representative(self, storage_kind: str, offset: int, size: int) -> int:
        """Representative varnode ref for a variable's storage, reusing an
        existing op-graph varnode at that location or creating one (so HighVariable
        reprefs and token varrefs point into the op graph)."""
        if storage_kind == "stack":
            rep = self._stack_rep.get(offset)
            if rep is None:
                rep = self._new_varnode(SPACE_STACK, offset, size)
                self._stack_rep[offset] = rep
                self._stack_members.setdefault(offset, []).append(rep)
            return rep
        rep = self._reg_rep.get(offset)
        if rep is None:
            rep = self._new_varnode(SPACE_REGISTER, offset, size)
            self._reg_rep[offset] = rep
            self._reg_members.setdefault(offset, []).append(rep)
        return rep

    def new_storage_varnode(self, storage_kind: str, offset: int, size: int) -> int:
        """A fresh (op-less) varnode at a storage location, for a variable that
        needs its own representative because another variable already claimed
        the existing varnodes there."""
        if storage_kind == "stack":
            ref = self._new_varnode(SPACE_STACK, offset, size)
            self._stack_members.setdefault(offset, []).append(ref)
        else:
            ref = self._new_varnode(SPACE_REGISTER, offset, size)
            self._reg_members.setdefault(offset, []).append(ref)
        return ref

    def occurrence_ref(self, varid, storage_kind: str, offset: int) -> int | None:
        """Varnode ref for one SSA occurrence (an AIL vvar id), provided it lives
        at the given storage -- so a token's varref can point at the exact SSA
        value it renders rather than the variable's representative."""
        if varid is None:
            return None
        ref = self._vvar_ref.get(varid)
        if ref is None:
            return None
        vn = self._by_ref.get(ref)
        if vn is not None and vn.space == storage_kind and vn.offset == offset:
            return ref
        return None

    def ops_by_block(self, block):
        """Ops belonging to a block, in order (by their time)."""
        if not hasattr(self, "_ops_by_time"):
            self._ops_by_time = {op.time: op for op in self.ops}
        return [self._ops_by_time[t] for t in block.op_times if t in self._ops_by_time]

    def op_time_at(self, ins_addr: int) -> int | None:
        """The (op) time of a representative op at an instruction address, for
        linking C tokens to the p-code op so navigation resolves the address."""
        if not hasattr(self, "_op_at_addr"):
            m: dict[int, int] = {}
            for op in self.ops:
                if op.ins_addr:
                    m.setdefault(op.ins_addr, op.time)
            self._op_at_addr = m
        return self._op_at_addr.get(ins_addr)

    # ------------------------------------------------------------ ops

    def _emit(self, opcode, ins_addr, output, inputs, space_input=None) -> int:
        time = self._next_time
        self._next_time += 1
        self.ops.append(Op(opcode, ins_addr, time, output, list(inputs), space_input))
        return time

    # ------------------------------------------------ expression lowering

    def _expr(self, e, ins_addr) -> int:
        """Return a varnode ref holding the value of expression e."""
        # ops take the expression's own instruction address when it has one, so
        # C tokens (which carry the expression's address) link to a matching op
        ins_addr = _ins_addr(e) or ins_addr
        cls = _cls(e)
        if cls == "VirtualVariable":
            return self._vvar(e)
        if cls == "Const":
            return self._const(_const_value(e), e.size or 1)
        if cls == "BinaryOp":
            opcode = _BINOP.get(getattr(e, "op", None))
            ops = list(getattr(e, "operands", []) or [])
            ins = [self._expr(o, ins_addr) for o in ops[:2]]
            out = self._temp(e.size or 1)
            self._emit(opcode if opcode is not None else COPY, ins_addr, out,
                       ins or [self._const(0, e.size or 1)])
            return out
        if cls == "UnaryOp":
            operand = (getattr(e, "operands", None) or [None])[0]
            src = self._expr(operand, ins_addr) if operand is not None else self._const(0, e.size or 1)
            opcode = {"Neg": INT_2COMP, "Not": INT_NEGATE, "BitwiseNeg": INT_NEGATE}.get(
                getattr(e, "op", None), COPY)
            out = self._temp(e.size or 1)
            self._emit(opcode, ins_addr, out, [src])
            return out
        if cls == "Convert":
            operand = (getattr(e, "operands", None) or [None])[0]
            src = self._expr(operand, ins_addr) if operand is not None else self._const(0, 1)
            frm = getattr(e, "from_bits", 0) or 0
            to = getattr(e, "to_bits", e.bits) or 0
            out = self._temp((to or 8) // 8)
            if to > frm:
                opcode = INT_SEXT if getattr(e, "is_signed", False) else INT_ZEXT
            elif to < frm:
                opcode = SUBPIECE
            else:
                opcode = COPY
            ins = [src] if opcode != SUBPIECE else [src, self._const(0, 4)]
            self._emit(opcode, ins_addr, out, ins)
            return out
        if cls == "Load":
            # approximate: the loaded value depends on the address expression
            # (a COPY preserves that data-flow edge without the LOAD space-id)
            addr = getattr(e, "addr", None)
            aref = self._expr(addr, ins_addr) if addr is not None else self._const(0, 8)
            out = self._temp(e.size or 1)
            self._emit(COPY, ins_addr, out, [aref])
            return out
        if cls == "Call":
            return self._call(e, ins_addr, want_output=True)
        # unmodelled expression: an undefined temporary
        return self._temp(getattr(e, "size", None) or 1)

    def _call(self, call, ins_addr, want_output) -> int | None:
        target = getattr(call, "target", None)
        if target is not None and _cls(target) == "Const":
            tref = self._const(_const_value(target), target.size or 8)
        elif target is not None:
            tref = self._expr(target, ins_addr)
        else:
            tref = self._const(0, 8)
        ins = [tref]
        for a in (getattr(call, "args", None) or []):
            ins.append(self._expr(a, ins_addr))
        out = self._temp(call.size or 8) if want_output else None
        self._emit(CALL, ins_addr, out, ins)
        return out

    # ------------------------------------------------- statement lowering

    def _stmt(self, st):
        cls = _cls(st)
        ins_addr = _ins_addr(st)
        if cls == "Assignment":
            dst = st.dst
            src = st.src
            if _cls(dst) != "VirtualVariable":
                # assignment to something we don't model as a varnode
                self._expr(src, ins_addr)
                return
            out = self._vvar(dst)
            scls = _cls(src)
            if scls == "VirtualVariable":
                self._emit(COPY, ins_addr, out, [self._vvar(src)])
            elif scls == "Const":
                self._emit(COPY, ins_addr, out, [self._const(_const_value(src), src.size or 1)])
            else:
                # let the operation write directly to the destination
                val = self._expr(src, ins_addr)
                self._emit(COPY, ins_addr, out, [val])
        elif cls == "Store":
            # approximate: evaluate address + data so their data-flow is present
            # (a real STORE needs a space-id input we don't model yet)
            addr = getattr(st, "addr", None)
            data = getattr(st, "data", None)
            if addr is not None:
                self._expr(addr, ins_addr)
            if data is not None:
                self._expr(data, ins_addr)
        elif cls == "ConditionalJump":
            cond = getattr(st, "condition", None)
            cref = self._expr(cond, ins_addr) if cond is not None else self._const(0, 1)
            self._emit(CBRANCH, ins_addr, None, [self._const(ins_addr, 8), cref])
        elif cls == "Jump":
            self._emit(BRANCH, ins_addr, None, [self._const(ins_addr, 8)])
        elif cls == "Return":
            rets = getattr(st, "ret_exprs", None) or []
            ins = [self._const(0, 8)]
            for r in rets:
                ins.append(self._expr(r, ins_addr))
            self._emit(RETURN, ins_addr, None, ins)
        elif cls == "Call":
            self._call(st, ins_addr, want_output=False)
        # Label / NoOp / unmodelled -> nothing

    # -------------------------------------------------------- graph build

    def translate(self, ail_graph):
        blocks = sorted(ail_graph.nodes(), key=lambda b: (b.addr, b.idx or 0))
        index_of = {id(b): i for i, b in enumerate(blocks)}
        for i, blk in enumerate(blocks):
            block = Block(index=i, addr=blk.addr, addr_last=blk.addr)
            self.blocks.append(block)
            first_time = self._next_time
            for st in blk.statements:
                _ins = _ins_addr(st)
                if _ins:
                    block.addr_last = max(block.addr_last, _ins)
                self._stmt(st)
            block.op_times = list(range(first_time, self._next_time))
        # in-edges (with reverse index = position among the source's out-edges)
        out_count: dict[int, int] = {}
        for src, dst in ail_graph.edges():
            si = index_of[id(src)]
            di = index_of[id(dst)]
            rev = out_count.get(si, 0)
            out_count[si] = rev + 1
            self.blocks[di].in_edges.append((si, rev))
        return self


def _cls(o) -> str:
    """Discriminate a Rust-ailment object by isinstance against marker classes."""
    import angr.ailment.expression as Ex
    import angr.ailment.statement as St

    for mod in (St, Ex):
        for nm in _CLASS_NAMES:
            c = getattr(mod, nm, None)
            if c is not None and isinstance(o, c):
                return nm
    return type(o).__name__


_CLASS_NAMES = (
    "Assignment", "Store", "ConditionalJump", "Jump", "Return", "Label", "Call",
    "VirtualVariable", "Const", "BinaryOp", "UnaryOp", "Convert", "Load",
)


def _ins_addr(st) -> int:
    tags = getattr(st, "tags", None) or {}
    return tags.get("ins_addr", 0) or 0


def _const_value(c) -> int:
    v = getattr(c, "value", 0)
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def _is_register(vvar) -> bool:
    try:
        return bool(vvar.oident) and isinstance(vvar.oident, tuple)
    except Exception:
        return False


def _reg_offset(vvar):
    if getattr(vvar, "was_reg", False):
        return vvar.reg_offset
    oid = getattr(vvar, "oident", None)
    if isinstance(oid, tuple) and len(oid) == 2:
        return oid[1]
    return None
