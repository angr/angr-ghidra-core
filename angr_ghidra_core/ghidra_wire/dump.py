"""Debug utility: parse a packed stream into a readable nested tree."""

from __future__ import annotations

from . import ids
from .packed import (
    ATTRIBUTE,
    ELEMENT_END,
    ELEMENT_START,
    HEADER_MASK,
    PackedDecoder,
)


class Element:
    def __init__(self, elem_id: int):
        self.id = elem_id
        self.name = ids.ELEMENT_NAMES.get(elem_id, f"elem#{elem_id}")
        self.attrs: list[tuple[str, object]] = []
        self.children: list[Element] = []

    def attr(self, name: str, default=None):
        for k, v in self.attrs:
            if k == name:
                return v
        return default

    def find(self, name: str):
        return [c for c in self.children if c.name == name]

    def first(self, name: str):
        for c in self.children:
            if c.name == name:
                return c
        return None

    def pretty(self, indent: int = 0, max_depth: int = 999) -> str:
        pad = "  " * indent
        attrs = " ".join(
            f"{k}={v!r}" for k, v in self.attrs
        )
        line = f"{pad}<{self.name}{' ' + attrs if attrs else ''}>"
        if not self.children or max_depth == 0:
            return line + (f" ({len(self.children)} children)" if self.children else "")
        return "\n".join(
            [line] + [c.pretty(indent + 1, max_depth - 1) for c in self.children]
        )


def parse_tree(data: bytes) -> list[Element]:
    """Parse a full packed stream into a list of root Elements."""
    dec = PackedDecoder(data)
    roots: list[Element] = []
    stack: list[Element] = []
    pos = 0
    while pos < len(data):
        header = data[pos]
        kind = header & HEADER_MASK
        if kind == ELEMENT_START:
            ident, pos = dec._read_id(pos)
            el = Element(ident)
            if stack:
                stack[-1].children.append(el)
            else:
                roots.append(el)
            stack.append(el)
        elif kind == ELEMENT_END:
            ident, pos = dec._read_id(pos)
            if stack and stack[-1].id == ident:
                stack.pop()
            else:
                raise ValueError(f"Mismatched element end {ident} at {pos}")
        elif kind == ATTRIBUTE:
            ident, vpos = dec._read_id(pos)
            value = dec._attr_value(vpos)
            pos = dec._skip_attr_value(vpos)
            name = ids.ATTRIBUTE_NAMES.get(ident, f"attr#{ident}")
            if stack:
                stack[-1].attrs.append((name, value))
        else:
            raise ValueError(f"Bad header byte {header:#x} at {pos}")
    return roots
