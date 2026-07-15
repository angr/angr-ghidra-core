"""Render a decompiler C-markup token tree (the second <function> element of a
decompileAt response) to plain C text — the equivalent of Ghidra's PrettyPrinter.
"""

from __future__ import annotations

from .dump import Element

TOKEN_ELEMENTS = {
    "syntax",
    "variable",
    "op",
    "funcname",
    "type",
    "field",
    "comment",
    "label",
    "value",
    "bitfield",
}

GROUP_ELEMENTS = {
    "function",
    "block",
    "statement",
    "funcproto",
    "return_type",
    "vardecl",
    "clang_document",
}


def render_c(markup: Element) -> str:
    """Flatten the token tree to text: tokens emit content, <break> emits
    newline + indent."""
    out: list[str] = []

    def walk(el: Element) -> None:
        if el.name == "break":
            indent = el.attr("indent", 0) or 0
            out.append("\n" + " " * indent)
        elif el.name in TOKEN_ELEMENTS:
            content = el.attr("XMLcontent", "")
            if content:
                out.append(str(content))
        elif el.name in GROUP_ELEMENTS or el.children:
            for child in el.children:
                walk(child)

    walk(markup)
    return "".join(out).strip("\n") + "\n"


def split_decompile_response(roots: list[Element]) -> tuple[Element | None, Element | None]:
    """Given the parsed <doc> of a decompileAt response, return
    (model_function, markup_function) mirroring DecompileResults' first/second
    <function> discrimination."""
    if not roots or roots[0].name != "doc":
        return None, None
    functions = roots[0].find("function")
    model = functions[0] if len(functions) > 0 else None
    markup = functions[1] if len(functions) > 1 else None
    return model, markup
