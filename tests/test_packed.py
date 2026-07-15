"""Unit tests for the packed encoding, including vectors hand-derived from the
format spec in PackedDecode.java (lines 24-76)."""

import pytest

from angr_ghidra_core.ghidra_wire import ids
from angr_ghidra_core.ghidra_wire.packed import (
    DecoderError,
    PackedDecoder,
    PackedEncoder,
    SpecialSpace,
)


def test_header_small_id():
    enc = PackedEncoder()
    enc.open_element(ids.ELEM_ADDR)  # id 11 <= 0x1f
    assert enc.to_bytes() == bytes([0x40 | 11])


def test_header_extended_id():
    enc = PackedEncoder()
    enc.open_element(ids.ELEM_DOC)  # id 229 > 0x1f
    # header: 0x40 | 0x20 | (229 >> 7) = 0x61 ; extension: (229 & 0x7f) | 0x80
    assert enc.to_bytes() == bytes([0x61, (229 & 0x7F) | 0x80])


def test_integer_encodings():
    enc = PackedEncoder()
    enc.open_element(ids.ELEM_ADDR)
    enc.write_unsigned(ids.ATTRIB_OFFSET, 0)  # length code 0, no data bytes
    enc.write_unsigned(ids.ATTRIB_SIZE, 0x7F)  # 1 byte
    enc.write_unsigned(ids.ATTRIB_ID, 0x80)  # 2 bytes
    enc.write_signed(ids.ATTRIB_INDEX, -5)
    enc.write_unsigned(ids.ATTRIB_FIRST, (1 << 64) - 1)  # 10 raw bytes
    enc.close_element(ids.ELEM_ADDR)
    dec = PackedDecoder(enc.to_bytes())
    el = dec.open_element()
    assert el == ids.ELEM_ADDR
    assert dec.read_attribute(ids.ATTRIB_OFFSET) == 0
    assert dec.read_attribute(ids.ATTRIB_SIZE) == 0x7F
    assert dec.read_attribute(ids.ATTRIB_ID) == 0x80
    assert dec.read_attribute(ids.ATTRIB_INDEX) == -5
    assert dec.read_attribute(ids.ATTRIB_FIRST) == (1 << 64) - 1
    dec.close_element(el)
    assert dec.at_end()


def test_integer_byte_level():
    # unsigned 0x80 -> type byte 0x42 (unsigned, len 2), bytes 0x81, 0x80
    enc = PackedEncoder()
    enc.write_unsigned(ids.ATTRIB_OFFSET, 0x80)
    data = enc.to_bytes()
    # ATTRIB_OFFSET id 16: header 0xc0|0x20|(16>>7=0)=0xe0, ext (16|0x80)=0x90
    assert data[:2] == bytes([0xC0 | 16]) or data[:1] == bytes([0xC0 | 16])
    # id 16 fits in 5 bits (<=0x1f) -> single header byte 0xd0
    assert data == bytes([0xC0 | 16, (4 << 4) | 2, 0x80 | 1, 0x80 | 0])


def test_bool_and_string_and_space():
    enc = PackedEncoder()
    enc.open_element(ids.ELEM_FUNCTION)
    enc.write_bool(ids.ATTRIB_READONLY, True)
    enc.write_bool(ids.ATTRIB_VOLATILE, False)
    enc.write_string(ids.ATTRIB_NAME, "main")
    enc.write_string(ids.ATTRIB_LABEL, "")
    enc.write_space(ids.ATTRIB_SPACE, 3)
    enc.write_special_space(ids.ATTRIB_METATYPE, 1)  # join
    enc.close_element(ids.ELEM_FUNCTION)

    dec = PackedDecoder(enc.to_bytes())
    el = dec.open_element(ids.ELEM_FUNCTION)
    assert dec.read_attribute(ids.ATTRIB_READONLY) is True
    assert dec.read_attribute(ids.ATTRIB_VOLATILE) is False
    assert dec.read_attribute(ids.ATTRIB_NAME) == "main"
    assert dec.read_attribute(ids.ATTRIB_LABEL) == ""
    assert dec.read_attribute(ids.ATTRIB_SPACE) == 3
    assert dec.read_attribute(ids.ATTRIB_METATYPE) == SpecialSpace(1)
    dec.close_element(el)


def test_nested_elements_and_skipping():
    enc = PackedEncoder()
    enc.open_element(ids.ELEM_DOC)
    enc.write_unsigned(ids.ATTRIB_ID, 42)
    enc.open_element(ids.ELEM_ADDR)
    enc.write_unsigned(ids.ATTRIB_OFFSET, 0x401000)
    enc.close_element(ids.ELEM_ADDR)
    enc.open_element(ids.ELEM_BLOCK)
    enc.open_element(ids.ELEM_OP)
    enc.write_unsigned(ids.ATTRIB_CODE, 1)
    enc.close_element(ids.ELEM_OP)
    enc.close_element(ids.ELEM_BLOCK)
    enc.close_element(ids.ELEM_DOC)

    dec = PackedDecoder(enc.to_bytes())
    doc = dec.open_element(ids.ELEM_DOC)
    assert dec.read_attribute(ids.ATTRIB_ID) == 42
    assert dec.peek_element() == ids.ELEM_ADDR
    dec.skip_element()
    assert dec.peek_element() == ids.ELEM_BLOCK
    blk = dec.open_element()
    dec.close_element_skipping(blk)  # skip the inner <op>
    assert dec.peek_element() == 0
    dec.close_element(doc)
    assert dec.at_end()


def test_no_zero_bytes():
    enc = PackedEncoder()
    enc.open_element(ids.ELEM_DOC)
    for val in (0, 1, 127, 128, 0x3FFF, 1 << 40, (1 << 64) - 1):
        enc.write_unsigned(ids.ATTRIB_OFFSET, val)
        enc.write_signed(ids.ATTRIB_SIZE, -val)
    enc.write_string(ids.ATTRIB_NAME, "hello é中")
    enc.close_element(ids.ELEM_DOC)
    assert 0 not in enc.to_bytes()


def test_missing_attribute_raises():
    enc = PackedEncoder()
    enc.open_element(ids.ELEM_ADDR)
    enc.close_element(ids.ELEM_ADDR)
    dec = PackedDecoder(enc.to_bytes())
    dec.open_element()
    with pytest.raises(DecoderError):
        dec.read_attribute(ids.ATTRIB_NAME)
