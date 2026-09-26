"""Where macula-py finds macula-go's shared library: the wheel's own copy, or
MACULA_LIBRARY_PATH when set; a missing library fails naming both."""

import pytest

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


def test_a_missing_packaged_copy_is_refused_naming_the_way_out(tmp_path, monkeypatch):
    monkeypatch.delenv("MACULA_LIBRARY_PATH", raising=False)
    with pytest.raises(OSError, match="no macula-py wheel for this platform"):
        library_path(package_dir=tmp_path)
