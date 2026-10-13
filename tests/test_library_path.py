"""Where macula-py finds macula-go's shared library: the wheel's own copy, or
MACULA_LIBRARY_PATH when set; a missing library fails naming both, and so does
a library speaking another wire than this macula-py's own."""

import pytest

from macula_py._abi import speaks_our_wire
from macula_py._library import library_file_name, library_path


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
