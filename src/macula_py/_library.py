"""Where macula-go's shared C ABI library is: the copy the platform wheel
carries in macula_py/_native/, or the file MACULA_LIBRARY_PATH names."""

from __future__ import annotations

import os
import sys
from pathlib import Path

_PACKAGE_NATIVE_DIR = Path(__file__).parent / "_native"


def library_file_name(platform: str = sys.platform) -> str:
    """The library's file name on platform (a sys.platform value)."""
    if platform.startswith("linux"):
        return "libmacula.so"
    if platform == "darwin":
        return "libmacula.dylib"
    if platform == "win32":
        return "macula.dll"
    raise OSError(f"macula-py: no macula-go library build for platform {platform!r}")


def library_path(package_dir: Path = _PACKAGE_NATIVE_DIR) -> Path:
    """The library file to load."""
    override = os.environ.get("MACULA_LIBRARY_PATH")
    if override:
        path = Path(override)
        if not path.is_file():
            raise OSError(f"macula-py: MACULA_LIBRARY_PATH names {path}, which is not a file")
        return path
    path = package_dir / library_file_name()
    if not path.is_file():
        raise OSError(
            f"macula-py: {path} is missing: there is no macula-py wheel for this platform "
            "installed. Build macula-go's cabi as a shared library and set MACULA_LIBRARY_PATH to it."
        )
    return path
