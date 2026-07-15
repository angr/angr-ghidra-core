"""Packed binary encoding, bit-exact to Ghidra's PackedEncode.java/PackedDecode.java
(and the C++ marshal.cc PackedEncode/PackedDecode).

Grammar (all bytes non-zero):
  01x iiiii             element start
  10x iiiii             element end
  11x iiiii             attribute start
where iiiii = high bits of the id if x (HEADEREXTEND) is set, in which case one
extension byte 1iiiiiii carries the low 7 bits; otherwise iiiii is the full id.

After an attribute start comes a type byte ttttllll:
  t: 1=bool 2=signed+ 3=signed- 4=unsigned 5=addr-space 6=special-space 7=string
  l: length code (integers: number of following 1iiiiiii bytes, big-end-first,
     0 encodes value 0; bool: 0/1; special-space: 0=stack 1=join 2=fspec 3=iop)
Strings: unsigned length integer then raw UTF-8 bytes.
"""

from __future__ import annotations

HEADER_MASK = 0xC0
ELEMENT_START = 0x40
ELEMENT_END = 0x80
ATTRIBUTE = 0xC0
HEADEREXTEND_MASK = 0x20
ELEMENTID_MASK = 0x1F
RAWDATA_MASK = 0x7F
RAWDATA_BITSPERBYTE = 7
RAWDATA_MARKER = 0x80
TYPECODE_SHIFT = 4
LENGTHCODE_MASK = 0xF
TYPECODE_BOOLEAN = 1
TYPECODE_SIGNEDINT_POSITIVE = 2
TYPECODE_SIGNEDINT_NEGATIVE = 3
TYPECODE_UNSIGNEDINT = 4
TYPECODE_ADDRESSSPACE = 5
TYPECODE_SPECIALSPACE = 6
TYPECODE_STRING = 7
SPECIALSPACE_STACK = 0
SPECIALSPACE_JOIN = 1
SPECIALSPACE_FSPEC = 2
SPECIALSPACE_IOP = 3
SPECIALSPACE_SPACEBASE = 4

_U64 = (1 << 64) - 1


class SpecialSpace:
    """Marker for stack/join/fspec/iop space values in decode results."""

    def __init__(self, code: int):
        self.code = code

    def __eq__(self, other):
        return isinstance(other, SpecialSpace) and self.code == other.code

    def __repr__(self):
        names = {0: "stack", 1: "join", 2: "fspec", 3: "iop", 4: "spacebase"}
        return f"<special:{names.get(self.code, self.code)}>"


class PackedEncoder:
    """Mirror of PackedEncode.java writing to a bytearray."""

    def __init__(self):
        self.buf = bytearray()

    def _header(self, header: int, ident: int) -> None:
        if ident > 0x1F:
            self.buf.append(header | HEADEREXTEND_MASK | (ident >> RAWDATA_BITSPERBYTE))
            self.buf.append((ident & RAWDATA_MASK) | RAWDATA_MARKER)
        else:
            self.buf.append(header | ident)

    def _integer(self, type_byte: int, val: int) -> None:
        # val is a non-negative magnitude, up to 64 bits
        assert 0 <= val <= _U64
        nbits = val.bit_length()
        len_code = (nbits + RAWDATA_BITSPERBYTE - 1) // RAWDATA_BITSPERBYTE
        self.buf.append(type_byte | len_code)
        for i in range(len_code - 1, -1, -1):
            self.buf.append(((val >> (i * RAWDATA_BITSPERBYTE)) & RAWDATA_MASK) | RAWDATA_MARKER)

    def open_element(self, elem_id: int) -> None:
        self._header(ELEMENT_START, elem_id)

    def close_element(self, elem_id: int) -> None:
        self._header(ELEMENT_END, elem_id)

    def write_bool(self, attrib_id: int, val: bool) -> None:
        self._header(ATTRIBUTE, attrib_id)
        self.buf.append(0x11 if val else 0x10)

    def write_signed(self, attrib_id: int, val: int) -> None:
        self._header(ATTRIBUTE, attrib_id)
        if val < 0:
            self._integer(TYPECODE_SIGNEDINT_NEGATIVE << TYPECODE_SHIFT, -val)
        else:
            self._integer(TYPECODE_SIGNEDINT_POSITIVE << TYPECODE_SHIFT, val)

    def write_unsigned(self, attrib_id: int, val: int) -> None:
        self._header(ATTRIBUTE, attrib_id)
        self._integer(TYPECODE_UNSIGNEDINT << TYPECODE_SHIFT, val & _U64)

    def write_string(self, attrib_id: int, val: str | bytes) -> None:
        data = val.encode("utf-8") if isinstance(val, str) else val
        self._header(ATTRIBUTE, attrib_id)
        self._integer(TYPECODE_STRING << TYPECODE_SHIFT, len(data))
        self.buf.extend(data)

    def write_space(self, attrib_id: int, index: int) -> None:
        """Basic address space by manager index (matches getUnique()/getIndex())."""
        self._header(ATTRIBUTE, attrib_id)
        self._integer(TYPECODE_ADDRESSSPACE << TYPECODE_SHIFT, index)

    def write_special_space(self, attrib_id: int, code: int) -> None:
        self._header(ATTRIBUTE, attrib_id)
        self.buf.append((TYPECODE_SPECIALSPACE << TYPECODE_SHIFT) | code)

    def write_opcode(self, attrib_id: int, opcode: int) -> None:
        # Java's writeOpcode uses the positive-signed-int typecode
        self._header(ATTRIBUTE, attrib_id)
        self._integer(TYPECODE_SIGNEDINT_POSITIVE << TYPECODE_SHIFT, opcode)

    def to_bytes(self) -> bytes:
        return bytes(self.buf)

    def is_empty(self) -> bool:
        return not self.buf


class DecoderError(Exception):
    pass


class PackedDecoder:
    """Event-level mirror of PackedDecode.java over an in-memory buffer.

    Semantics match the Java decoder: after open_element(), attributes of that
    element may be read by id in any order; child elements follow the attribute
    run; close_element skips any unread portion up to the matching end marker.
    """

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0
        # start of attribute run for the innermost open element
        self._attr_start: list[int] = []

    # --- low-level ---

    def _byte(self, pos: int) -> int:
        if pos >= len(self.data):
            raise DecoderError("Unexpected end of stream")
        return self.data[pos]

    def _read_id(self, pos: int) -> tuple[int, int]:
        """Return (id, next_pos) for header at pos."""
        header = self._byte(pos)
        ident = header & ELEMENTID_MASK
        pos += 1
        if header & HEADEREXTEND_MASK:
            ident = (ident << RAWDATA_BITSPERBYTE) | (self._byte(pos) & RAWDATA_MASK)
            pos += 1
        return ident, pos

    def _read_integer(self, pos: int, length: int) -> tuple[int, int]:
        res = 0
        for _ in range(length):
            res = (res << RAWDATA_BITSPERBYTE) | (self._byte(pos) & RAWDATA_MASK)
            pos += 1
        return res, pos

    def _skip_attr_value(self, pos: int) -> int:
        """pos points at the type byte; return position after the value."""
        type_byte = self._byte(pos)
        pos += 1
        typecode = type_byte >> TYPECODE_SHIFT
        length = type_byte & LENGTHCODE_MASK
        if typecode in (TYPECODE_BOOLEAN, TYPECODE_SPECIALSPACE):
            return pos
        if typecode == TYPECODE_STRING:
            strlen, pos = self._read_integer(pos, length)
            return pos + strlen
        return pos + length

    def _attr_value(self, pos: int):
        """pos points at the type byte; decode the value."""
        type_byte = self._byte(pos)
        pos += 1
        typecode = type_byte >> TYPECODE_SHIFT
        length = type_byte & LENGTHCODE_MASK
        if typecode == TYPECODE_BOOLEAN:
            return bool(length)
        if typecode == TYPECODE_SIGNEDINT_POSITIVE:
            val, _ = self._read_integer(pos, length)
            return val
        if typecode == TYPECODE_SIGNEDINT_NEGATIVE:
            val, _ = self._read_integer(pos, length)
            return -val
        if typecode == TYPECODE_UNSIGNEDINT:
            val, _ = self._read_integer(pos, length)
            return val
        if typecode == TYPECODE_ADDRESSSPACE:
            val, _ = self._read_integer(pos, length)
            return val
        if typecode == TYPECODE_SPECIALSPACE:
            return SpecialSpace(length)
        if typecode == TYPECODE_STRING:
            strlen, pos = self._read_integer(pos, length)
            return self.data[pos : pos + strlen].decode("utf-8")
        raise DecoderError(f"Bad type byte {type_byte:#x}")

    # --- element API ---

    def peek_element(self) -> int:
        """Id of the next element start, or 0 if next is not an element start."""
        if self.pos >= len(self.data):
            return 0
        header = self.data[self.pos]
        if (header & HEADER_MASK) != ELEMENT_START:
            return 0
        ident, _ = self._read_id(self.pos)
        return ident

    def open_element(self, expect: int | None = None) -> int:
        header = self._byte(self.pos)
        if (header & HEADER_MASK) != ELEMENT_START:
            raise DecoderError(f"Expected element start at {self.pos}")
        ident, self.pos = self._read_id(self.pos)
        if expect is not None and ident != expect:
            raise DecoderError(f"Expected element {expect}, got {ident}")
        # skip past the attribute run to find children; remember where attrs began
        self._attr_start.append(self.pos)
        pos = self.pos
        while pos < len(self.data) and (self._byte(pos) & HEADER_MASK) == ATTRIBUTE:
            _, vpos = self._read_id(pos)
            pos = self._skip_attr_value(vpos)
        self.pos = pos
        return ident

    def close_element(self, elem_id: int) -> None:
        header = self._byte(self.pos)
        if (header & HEADER_MASK) != ELEMENT_END:
            raise DecoderError(f"Expected element end at {self.pos} (closing {elem_id})")
        ident, self.pos = self._read_id(self.pos)
        if ident != elem_id:
            raise DecoderError(f"Expected end of element {elem_id}, got {ident}")
        self._attr_start.pop()

    def close_element_skipping(self, elem_id: int) -> None:
        """Skip remaining children until the matching end marker is consumed."""
        depth = 0
        while True:
            header = self._byte(self.pos)
            kind = header & HEADER_MASK
            if kind == ELEMENT_START:
                _, self.pos = self._read_id(self.pos)
                depth += 1
            elif kind == ELEMENT_END:
                ident, self.pos = self._read_id(self.pos)
                if depth == 0:
                    if ident != elem_id:
                        raise DecoderError(f"Expected end of {elem_id}, got {ident}")
                    self._attr_start.pop()
                    return
                depth -= 1
            elif kind == ATTRIBUTE:
                _, vpos = self._read_id(self.pos)
                self.pos = self._skip_attr_value(vpos)
            else:
                raise DecoderError(f"Bad header byte at {self.pos}")

    def skip_element(self) -> None:
        """Skip the next element entirely (must be positioned at an element start)."""
        ident = self.open_element()
        self.close_element_skipping(ident)

    # --- attribute API (operate on innermost open element) ---

    def attributes(self):
        """Yield (attrib_id, value) for the innermost open element, in order."""
        pos = self._attr_start[-1]
        while pos < len(self.data) and (self._byte(pos) & HEADER_MASK) == ATTRIBUTE:
            ident, vpos = self._read_id(pos)
            yield ident, self._attr_value(vpos)
            pos = self._skip_attr_value(vpos)

    def read_attribute(self, attrib_id: int):
        for ident, value in self.attributes():
            if ident == attrib_id:
                return value
        raise DecoderError(f"Attribute {attrib_id} is not present")

    def read_opt(self, attrib_id: int, default=None):
        for ident, value in self.attributes():
            if ident == attrib_id:
                return value
        return default

    def has_attribute(self, attrib_id: int) -> bool:
        return any(ident == attrib_id for ident, _ in self.attributes())

    def at_end(self) -> bool:
        return self.pos >= len(self.data)
