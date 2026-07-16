"""Multi-word type names must survive Ghidra's IllegalCharCppTransformer:
identifier words become <type> tokens, separators become <syntax> tokens."""
from angr_ghidra_core.core.emit import ResponseEmitter, TYPE_COLOR
from angr_ghidra_core.ghidra_wire.packed import PackedEncoder
from angr_ghidra_core.ghidra_wire.dump import parse_tree


def _emit(text):
    em = ResponseEmitter(space_ram=2, space_register=3, return_register=(0, 8), coretype_ids={})
    enc = PackedEncoder()
    enc.open_element(3)  # any wrapping element so parse_tree has a root
    em._emit_type_token(enc, text)
    enc.close_element(3)
    return parse_tree(enc.to_bytes())[0].children


def _rendered(text):
    return "".join(c.attr("XMLcontent", "") for c in _emit(text))


def test_multiword_type_split_preserves_text():
    assert _rendered("unsigned long long") == "unsigned long long"
    assert _rendered("unsigned int") == "unsigned int"


def test_words_are_type_tokens_separators_are_syntax():
    parts = _emit("unsigned int")
    kinds = [(c.name, c.attr("XMLcontent")) for c in parts]
    assert kinds == [("type", "unsigned"), ("syntax", " "), ("type", "int")]
    # separators must NOT be type tokens (those get space-mangled by Ghidra)
    for c in parts:
        if c.name == "type":
            assert " " not in c.attr("XMLcontent")


def test_pointer_star_is_syntax():
    parts = _emit("char *")
    assert [c.name for c in parts] == ["type", "syntax"]
    assert _rendered("char *") == "char *"


def test_single_word_unchanged():
    parts = _emit("undefined8")
    assert len(parts) == 1 and parts[0].name == "type"
    assert parts[0].attr("XMLcontent") == "undefined8"
