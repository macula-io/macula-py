"""The ctypes declarations are the header's, function for function: a
function missing on either side, or declared with other types, fails here
naming it, and so does an ABI version that is not the header's."""

import re
from pathlib import Path

from macula_py._abi import ABI_VERSION, FUNCTIONS

HEADER = Path(__file__).parent.parent / "abi" / "macula.h"


def _normalize(c_type: str) -> str:
    c_type = re.sub(r"\s+", " ", c_type.strip())
    c_type = re.sub(r"\s*\*\s*", "*", c_type)
    return c_type


def _parameter_type(parameter: str) -> str:
    parameter = parameter.strip()
    array = re.search(r"\[\d*\]\s*$", parameter)
    if array:
        parameter = parameter[: array.start()]
    # Drop the parameter's name: the last identifier.
    c_type = re.sub(r"[A-Za-z_][A-Za-z0-9_]*\s*$", "", parameter)
    return _normalize(c_type) + ("*" if array else "")


def header_functions() -> dict[str, tuple[str, list[str]]]:
    text = HEADER.read_text()
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    text = re.sub(r"^\s*#.*$", "", text, flags=re.MULTILINE)
    text = text.replace('extern "C" {', "").replace("}", "")
    functions = {}
    for declaration in text.split(";"):
        declaration = " ".join(declaration.split())
        m = re.fullmatch(r"(.+?[\s*])(macula_[a-z0-9_]+)\s*\((.*)\)", declaration)
        if not m:
            continue
        returns = _normalize(m[1])
        parameters = [] if m[3].strip() in ("", "void") else [_parameter_type(p) for p in m[3].split(",")]
        functions[m[2]] = (returns, parameters)
    return functions


def test_the_header_parses_to_a_plausible_function_set():
    functions = header_functions()
    assert "macula_abi_version" in functions
    assert functions["macula_pool_call"][0] == "char*"
    assert functions["macula_key_node_id"][1] == ["macula_handle", "uint8_t*", "char**"]


def test_every_header_function_is_declared_with_its_types():
    header = header_functions()
    declared = {name: (_normalize(r), [_normalize(a) for a in args]) for name, (r, args) in FUNCTIONS.items()}
    assert sorted(set(header) - set(declared)) == [], "declared nowhere in macula_py._abi"
    assert sorted(set(declared) - set(header)) == [], "declared in macula_py._abi but not in the header"
    for name, signature in header.items():
        assert declared[name] == signature, name


def test_the_abi_version_is_the_headers():
    m = re.search(r"#define MACULA_ABI_VERSION (\d+)", HEADER.read_text())
    assert m is not None
    assert ABI_VERSION == int(m[1])
