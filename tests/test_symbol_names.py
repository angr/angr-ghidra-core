"""clean_symbol_name strips Ghidra's getCodeLabel namespace prefix."""
from angr_ghidra_core.core.angr_core import clean_symbol_name


def test_external_prefix_stripped():
    assert clean_symbol_name("<EXTERNAL>_atoi") == "atoi"
    assert clean_symbol_name("<EXTERNAL>_printf") == "printf"


def test_nested_namespace_segments_stripped():
    assert clean_symbol_name("<EXTERNAL>_<libc.so.6>_strlen") == "strlen"


def test_plain_names_untouched():
    assert clean_symbol_name("authenticate") == "authenticate"
    assert clean_symbol_name("sub_401050") == "sub_401050"
    # a namespace without angle brackets is left as-is (informative, not ugly)
    assert clean_symbol_name("MyClass_method") == "MyClass_method"


def test_empty():
    assert clean_symbol_name("") == ""
