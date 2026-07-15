"""Address element helpers (mirror of AddressXML.java for the packed encoding)."""

from __future__ import annotations

from dataclasses import dataclass

from . import ids
from .packed import PackedDecoder, PackedEncoder, SpecialSpace


@dataclass(frozen=True)
class Addr:
    """An address as (space index, offset). Space semantics come from the tspec."""

    space: int | SpecialSpace
    offset: int

    def __repr__(self):
        return f"Addr({self.space}:{self.offset:#x})"


def encode_addr(enc: PackedEncoder, addr: Addr) -> None:
    enc.open_element(ids.ELEM_ADDR)
    encode_addr_attributes(enc, addr)
    enc.close_element(ids.ELEM_ADDR)


def encode_addr_attributes(enc: PackedEncoder, addr: Addr, size: int | None = None) -> None:
    if isinstance(addr.space, SpecialSpace):
        enc.write_special_space(ids.ATTRIB_SPACE, addr.space.code)
    else:
        enc.write_space(ids.ATTRIB_SPACE, addr.space)
    enc.write_unsigned(ids.ATTRIB_OFFSET, addr.offset)
    if size is not None:
        enc.write_signed(ids.ATTRIB_SIZE, size)


def decode_addr(dec: PackedDecoder) -> tuple[Addr, dict]:
    """Open+close the next element, returning the address and all its attributes.

    Handles the generic "any element with space/offset attributes" form of
    AddressXML.decode. Extra attributes (e.g. size) are in the returned dict.
    """
    el = dec.open_element()
    attrs = dict(dec.attributes())
    dec.close_element_skipping(el)
    return (
        Addr(attrs.get(ids.ATTRIB_SPACE), attrs.get(ids.ATTRIB_OFFSET, 0)),
        attrs,
    )


def decode_addr_in_element(dec: PackedDecoder) -> Addr:
    """Read space/offset attributes of the already-open element."""
    attrs = dict(dec.attributes())
    return Addr(attrs.get(ids.ATTRIB_SPACE), attrs.get(ids.ATTRIB_OFFSET, 0))
