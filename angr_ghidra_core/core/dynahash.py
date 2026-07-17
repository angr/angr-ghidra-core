"""Port of Ghidra's DynamicHash over our emitted p-code op graph.

Ghidra identifies varnodes that have no stable storage address (SSA temporaries,
non-addr-tied stack slots) by hashing the local def-use neighborhood of the
varnode: renames/retypes of such variables are stored in the DB as a 64-bit hash
plus the address of the op most closely associated with the varnode, and come
back to the decompiler core as `<hash val=...>` symbols. The C++ core recomputes
the hash over its own syntax tree to find the varnode; we do exactly the same
over the op graph produced by PcodeTranslator.

This must be a *faithful* port of
Ghidra/Framework/SoftwareModeling/.../pcode/DynamicHash.java -- Ghidra computed
the stored hash over the very graph we emitted (decoded back into Java objects),
so bit-identical CRC math, edge ordering, and candidate gathering are what make
the lookup succeed. Where the Java has quirks (e.g. `uniqueHash` keeps the hash
of the last method tried even when an earlier method's candidate list won), we
replicate them.
"""

from __future__ import annotations


def _build_crc_table():
    # the standard CRC-32 table (poly 0xEDB88320), == SimpleCRC32.crc32tab
    tab = []
    for n in range(256):
        c = n
        for _ in range(8):
            c = (0xEDB88320 ^ (c >> 1)) if c & 1 else (c >> 1)
        tab.append(c)
    return tab


_CRC32TAB = _build_crc_table()


def _crc(reg: int, val: int) -> int:
    # SimpleCRC32.hashOneByte: crc32tab[(hashcode ^ val) & 0xff] ^ (hashcode >>> 8)
    return _CRC32TAB[(reg ^ val) & 0xFF] ^ (reg >> 8)


def _build_transtable():
    """transtable[opcode] -> hashed opcode (0 = skip op). Identity for most
    opcodes; comparison/arith variants lump together exactly as in Java."""
    tab = {i: i for i in range(0, 67)}
    tab[0] = 0
    tab[12] = 11   # INT_NOTEQUAL -> INT_EQUAL
    tab[14] = 13   # INT_SLESSEQUAL -> INT_SLESS
    tab[16] = 15   # INT_LESSEQUAL -> INT_LESS
    tab[20] = 19   # INT_SUB -> INT_ADD
    tab[29] = 32   # INT_LEFT -> INT_MULT
    tab[42] = 41   # FLOAT_NOTEQUAL -> FLOAT_EQUAL
    tab[44] = 43   # FLOAT_LESSEQUAL -> FLOAT_LESS
    tab[45] = 0    # unused slot
    tab[50] = 47   # FLOAT_SUB -> FLOAT_ADD
    tab[64] = 0    # CAST is skipped
    tab[65] = 19   # PTRADD -> INT_ADD
    tab[66] = 19   # PTRSUB -> INT_ADD
    return tab


_TRANSTABLE = _build_transtable()


def _trans(opcode: int) -> int:
    return _TRANSTABLE.get(opcode, 0)


class DynamicHasher:
    """Hash calculation and hash->varnode lookup over a PcodeTranslator graph.

    Varnodes are identified by their integer ref (create-index); the graph
    indices mirror what Ghidra's Java decode builds: defs (one per varnode),
    descendants in op-decode order with one entry per input slot, ops at an
    instruction address ordered by their time, and each op's order within its
    basic block (the SequenceNumber order used for edge sorting).
    """

    _MAX_DUPLICATES = 8

    def __init__(self, translator, addr_bytes: int = 8):
        self._vn = translator._by_ref
        self._addr_bytes = addr_bytes
        self._def: dict[int, object] = {}
        self._descend: dict[int, list] = {}
        self._ops_at: dict[int, list] = {}
        self._order: dict[int, int] = {}
        for blk in translator.blocks:
            for i, t in enumerate(blk.op_times):
                self._order[t] = i
        for op in sorted(translator.ops, key=lambda o: o.time):
            if op.output is not None:
                self._def[op.output] = op
            for ref in op.inputs:
                self._descend.setdefault(ref, []).append(op)
            self._ops_at.setdefault(op.ins_addr, []).append(op)

    # ------------------------------------------------------------ hashing

    def calc_hash(self, root: int, method: int) -> tuple[int, int | None]:
        """DynamicHash.calcHash(Varnode, method): hash the def-use neighborhood
        of the given varnode ref. Returns (hash, op address) -- (0, None) when
        the varnode has no attached ops."""
        opedge: list[tuple] = []    # (op, slot); slot -1 = output edge
        markvn: list[int] = []
        markop: list = []
        vnedge: list[int] = [root]
        seen: set = set()
        state = {"vnproc": 0, "opproc": 0, "opedgeproc": 0}

        def gather_vn():
            for r in vnedge:
                key = ("v", r)
                if key in seen:
                    continue
                markvn.append(r)
                seen.add(key)
            vnedge.clear()

        def gather_op():
            i = state["opedgeproc"]
            while i < len(opedge):
                op = opedge[i][0]
                key = ("o", id(op))
                if key not in seen:
                    markop.append(op)
                    seen.add(key)
                i += 1
            state["opedgeproc"] = i

        def build_vn_up(r):
            while True:
                op = self._def.get(r)
                if op is None:
                    return
                if _trans(op.opcode) != 0:
                    break
                if not op.inputs:
                    return
                r = op.inputs[0]
            opedge.append((op, -1))

        def build_vn_down(r):
            newedge = []
            for op in self._descend.get(r, ()):
                tmp = r
                while _trans(op.opcode) == 0:
                    tmp = op.output
                    if tmp is None:
                        op = None
                        break
                    d = self._descend.get(tmp, ())
                    op = d[0] if len(d) == 1 else None
                    if op is None:
                        break
                if op is None:
                    continue
                try:
                    slot = op.inputs.index(tmp)
                except ValueError:
                    continue
                newedge.append((op, slot))
            if len(newedge) > 1:
                newedge.sort(key=lambda e: (e[0].ins_addr,
                                            self._order.get(e[0].time, 0), e[1]))
            opedge.extend(newedge)

        def build_op_up(op):
            vnedge.extend(op.inputs)

        def build_op_down(op):
            if op.output is not None:
                vnedge.append(op.output)

        gather_vn()
        for i in range(state["vnproc"], len(markvn)):
            build_vn_up(markvn[i])
        while state["vnproc"] < len(markvn):
            build_vn_down(markvn[state["vnproc"]])
            state["vnproc"] += 1

        if method in (1, 3):
            gather_op()
            while state["opproc"] < len(markop):
                build_op_up(markop[state["opproc"]])
                state["opproc"] += 1
            gather_vn()
            while state["vnproc"] < len(markvn):
                (build_vn_up if method == 1 else build_vn_down)(markvn[state["vnproc"]])
                state["vnproc"] += 1
        elif method == 2:
            gather_op()
            while state["opproc"] < len(markop):
                build_op_down(markop[state["opproc"]])
                state["opproc"] += 1
            gather_vn()
            while state["vnproc"] < len(markvn):
                build_vn_down(markvn[state["vnproc"]])
                state["vnproc"] += 1

        return self._piece_together(root, method, opedge)

    def _piece_together(self, root: int, method: int, opedge) -> tuple[int, int | None]:
        if not opedge:
            return 0, None
        rootvn = self._vn[root]
        reg = 0x3BA0FE06
        reg = _crc(reg, rootvn.size)
        if rootvn.space == "const":
            val = rootvn.offset
            for _ in range(rootvn.size):
                reg = _crc(reg, val)
                val >>= 8
        for op, slot in opedge:
            reg = _crc(reg, slot)
            reg = _crc(reg, _trans(op.opcode))
            val = op.ins_addr
            for _ in range(self._addr_bytes):
                reg = _crc(reg, val)
                val >>= 8

        # find the op directly attached to root (all others are via skip ops)
        sel = None
        for op, slot in opedge:
            if slot < 0 and op.output == root:
                sel = (op, slot)
                break
            if 0 <= slot < len(op.inputs) and op.inputs[slot] == root:
                sel = (op, slot)
                break
        attached = sel is not None
        if sel is None:
            sel = opedge[0]
        op, slot = sel

        h = 0 if attached else 1
        h = (h << 4) | (method & 0xF)
        h = (h << 7) | (_trans(op.opcode) & 0x7F)
        h = (h << 5) | (slot & 0x1F)
        h = (h << 32) | (reg & 0xFFFFFFFF)
        return h, op.ins_addr

    # ------------------------------------------------------------- lookup

    @staticmethod
    def _comparable(h: int) -> int:
        return h & 0xFFFFFFFF

    def _gather_first_level(self, addr: int, h: int) -> list[int]:
        """gatherFirstLevelVars: candidate varnodes at an instruction address
        matching the hash's opcode/slot/attachment."""
        opc = (h >> 37) & 0x7F
        slot = (h >> 32) & 0x1F
        if slot == 31:
            slot = -1
        notattached = bool((h >> 48) & 1)
        out: list[int] = []
        for op in self._ops_at.get(addr, ()):
            if _trans(op.opcode) != opc:
                continue
            if slot < 0:
                r = op.output
                if r is None:
                    continue
                if notattached:
                    d = self._descend.get(r, ())
                    if len(d) == 1 and _trans(d[0].opcode) == 0:
                        r2 = d[0].output
                        if r2 is None:
                            continue
                        r = r2
                out.append(r)
            elif slot < len(op.inputs):
                r = op.inputs[slot]
                if notattached:
                    dop = self._def.get(r)
                    if dop is not None and _trans(dop.opcode) == 0 and dop.inputs:
                        r = dop.inputs[0]
                out.append(r)
        seen: set[int] = set()
        res = []
        for r in out:
            if r not in seen:
                seen.add(r)
                res.append(r)
        return res

    def find_varnode(self, addr: int, h: int) -> int | None:
        """DynamicHash.findVarnode: resolve a stored (address, hash) pair to the
        varnode ref it identifies, or None."""
        method = (h >> 44) & 0xF
        total = ((h >> 52) & 7) + 1
        pos = (h >> 49) & 7
        h_clear = h & ~(0x3F << 49)
        matches = [r for r in self._gather_first_level(addr, h_clear)
                   if self._comparable(self.calc_hash(r, method)[0])
                   == self._comparable(h_clear)]
        if total != len(matches):
            return None
        return matches[pos]

    def unique_hash(self, root: int) -> tuple[int, int | None]:
        """DynamicHash.uniqueHash(Varnode, fd): the hash Ghidra stores for an
        edit -- cycles methods 0-3 until few enough collisions, then bakes the
        position/total into the hash. (Used for self-tests; consumption only
        needs find_varnode.)"""
        champion = None
        tmphash, tmpaddr = 0, None
        for method in range(4):
            h, a = self.calc_hash(root, method)
            if h == 0:
                return 0, None
            tmphash, tmpaddr = h, a
            lst = []
            for r in self._gather_first_level(a, h):
                h2, _ = self.calc_hash(r, method)
                if self._comparable(h2) == self._comparable(h):
                    lst.append(r)
                    if len(lst) > self._MAX_DUPLICATES:
                        break
            if len(lst) <= self._MAX_DUPLICATES and \
                    (champion is None or len(lst) < len(champion)):
                champion = lst
                if len(champion) == 1:
                    break
        if not champion:
            return 0, None
        total = len(champion) - 1
        if root not in champion:
            return 0, None
        pos = champion.index(root)
        return tmphash | (pos << 49) | (total << 52), tmpaddr
