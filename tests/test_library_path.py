"""Where macula-py finds macula-go's shared library: the wheel's own copy, or
MACULA_LIBRARY_PATH when set; a missing library fails naming both, and so does
a library speaking another wire than this macula-py's own.

What `Native` says when it refuses such a library, and the order it refuses in,
is here too, against a stand-in library rather than a loaded one.
"""

import ctypes

import pytest

from macula_py._abi import ABI_VERSION, FUNCTIONS, WIRE_VERSION, speaks_our_wire
from macula_py._library import library_file_name, library_path
from macula_py._native import Native
from macula_py._wire import MaculaError


class _StandInLibrary:
    """A library as ctypes hands it over: every declared function present, and
    the three version functions answering what the test sets. A None is the
    NULL a C function returns for a string it does not have."""

    def __init__(self, abi: int, release: str | None = "v0.27.0-rc.3", wire: str | None = "1.0") -> None:
        for name in FUNCTIONS:
            setattr(self, name, lambda *args: 0)
        self.macula_abi_version = lambda: abi
        # ctypes hands a const char * back as bytes, and a NULL as None.
        self.macula_library_version = lambda: None if release is None else release.encode()
        self.macula_wire_version = lambda: None if wire is None else wire.encode()


def _native_over(monkeypatch, library: _StandInLibrary, path: str = "/nonexistent/libmacula.so") -> Native:
    """Native over the stand-in, in place of the dlopen the loader would do."""
    monkeypatch.setattr(ctypes, "CDLL", lambda _path: library)
    return Native(path)


def test_a_library_of_another_abi_is_refused_naming_both(monkeypatch):
    with pytest.raises(MaculaError) as raised:
        _native_over(monkeypatch, _StandInLibrary(abi=ABI_VERSION + 1))
    message = str(raised.value)
    assert f"macula C ABI {ABI_VERSION + 1}" in message
    assert f"binds ABI {ABI_VERSION}" in message
    assert "/nonexistent/libmacula.so" in message


def test_a_library_of_another_wire_is_refused_naming_its_release_and_wire(monkeypatch):
    with pytest.raises(MaculaError) as raised:
        _native_over(monkeypatch, _StandInLibrary(abi=ABI_VERSION, release="v0.26.0", wire="0.13"))
    message = str(raised.value)
    assert "v0.26.0" in message
    assert "wire 0.13" in message
    assert f"speaks wire {WIRE_VERSION}" in message


def test_the_abi_is_checked_before_the_wire(monkeypatch):
    """A library wrong in both is refused for the ABI: the version string it
    would have to speak is not read before it."""
    with pytest.raises(MaculaError, match="macula C ABI"):
        _native_over(monkeypatch, _StandInLibrary(abi=ABI_VERSION + 1, release="v0.26.0", wire="0.13"))


def test_a_library_reporting_no_release_is_refused_naming_itself(monkeypatch):
    with pytest.raises(MaculaError) as raised:
        _native_over(monkeypatch, _StandInLibrary(abi=ABI_VERSION, release=None))
    message = str(raised.value)
    assert "/nonexistent/libmacula.so" in message
    assert "macula_library_version" in message


def test_a_library_reporting_no_wire_is_refused_naming_itself(monkeypatch):
    with pytest.raises(MaculaError) as raised:
        _native_over(monkeypatch, _StandInLibrary(abi=ABI_VERSION, wire=None))
    message = str(raised.value)
    assert "/nonexistent/libmacula.so" in message
    assert "macula_wire_version" in message


def test_a_library_of_our_wire_is_taken(monkeypatch):
    """The other side of it: the same stand-in, answering this wire."""
    assert _native_over(monkeypatch, _StandInLibrary(abi=ABI_VERSION)).wire == WIRE_VERSION


@pytest.mark.parametrize(
    ("platform", "name"),
    [("linux", "libmacula.so"), ("darwin", "libmacula.dylib"), ("win32", "macula.dll")],
)
def test_the_file_name_follows_the_platform(platform, name):
    assert library_file_name(platform) == name


def test_an_unsupported_platform_is_refused_naming_it():
    with pytest.raises(OSError, match="freebsd"):
        library_file_name("freebsd14")


def test_the_environment_override_wins(tmp_path, monkeypatch):
    lib = tmp_path / "custom.so"
    lib.write_bytes(b"")
    monkeypatch.setenv("MACULA_LIBRARY_PATH", str(lib))
    assert library_path() == lib


def test_an_override_naming_a_missing_file_is_refused(tmp_path, monkeypatch):
    monkeypatch.setenv("MACULA_LIBRARY_PATH", str(tmp_path / "absent.so"))
    with pytest.raises(OSError, match="MACULA_LIBRARY_PATH"):
        library_path()


def test_without_an_override_the_packaged_copy_is_used(tmp_path, monkeypatch):
    monkeypatch.delenv("MACULA_LIBRARY_PATH", raising=False)
    packaged = tmp_path / library_file_name()
    packaged.write_bytes(b"")
    assert library_path(package_dir=tmp_path) == packaged


@pytest.mark.parametrize("wire", ["1.0", "1.1"])
def test_a_library_of_our_wire_major_is_taken(wire):
    """Every wire 1.x peer shares the frozen core: a 1.1 library reaches this
    node without an upgrade (cabi's CONTRACT.md)."""
    assert speaks_our_wire(wire)


@pytest.mark.parametrize("wire", ["2.0", "0.9", ""])
def test_a_library_of_another_wire_major_is_refused(wire):
    assert not speaks_our_wire(wire)


def test_a_missing_packaged_copy_is_refused_naming_the_way_out(tmp_path, monkeypatch):
    monkeypatch.delenv("MACULA_LIBRARY_PATH", raising=False)
    with pytest.raises(OSError, match="no macula-py wheel for this platform"):
        library_path(package_dir=tmp_path)
