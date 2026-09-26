"""macula-go's shared library, loaded once with ctypes and declared from
_abi. A library built for another ABI version is refused on load.

invoke() calls one function with the trailing err_out the contract gives
every fallible call, and raises the error its JSON names. Strings and byte
buffers the library returns are copied and freed here, so nothing above
this module touches library memory.
"""

from __future__ import annotations

import ctypes
import threading
from typing import Any

from macula_py._abi import ABI_VERSION, FUNCTIONS, LIBRARY_FLOOR
from macula_py._library import library_path
from macula_py._wire import MaculaError, native_error

_C_TYPES: dict[str, Any] = {
    "void": None,
    "int32_t": ctypes.c_int32,
    "int64_t": ctypes.c_int64,
    "uint64_t": ctypes.c_uint64,
    "size_t": ctypes.c_size_t,
    "macula_handle": ctypes.c_size_t,
    # Returned memory stays a raw address, to be copied and freed.
    "char*": ctypes.c_void_p,
    "uint8_t*": ctypes.c_void_p,
    "const char*": ctypes.c_char_p,
    "const uint8_t*": ctypes.c_char_p,
    "size_t*": ctypes.POINTER(ctypes.c_size_t),
    "int32_t*": ctypes.POINTER(ctypes.c_int32),
    "macula_handle*": ctypes.POINTER(ctypes.c_size_t),
    "char**": ctypes.POINTER(ctypes.c_void_p),
}


class Native:
    """The loaded library."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.lib = ctypes.CDLL(path)
        for name, (returns, parameters) in FUNCTIONS.items():
            try:
                function = getattr(self.lib, name)
            except AttributeError:
                # New functions keep the ABI version, so an older library
                # passes that check and lacks them: name the floor.
                raise MaculaError(
                    f"macula-py: {path} has no {name}; this macula-py needs macula-go {LIBRARY_FLOOR}'s library or later"
                ) from None
            function.restype = _C_TYPES[returns]
            function.argtypes = [_C_TYPES[p] for p in parameters]
        version = self.lib.macula_abi_version()
        if version != ABI_VERSION:
            raise MaculaError(
                f"macula-py: {path} is macula C ABI {version}, and this macula-py binds ABI {ABI_VERSION}"
            )
        self.cancels = _Cancels(self.lib)

    def invoke(self, name: str, *args: Any) -> Any:
        """name(*args, &err_out), raising the error err_out names."""
        err = ctypes.c_void_p(None)
        result = getattr(self.lib, name)(*args, ctypes.byref(err))
        if err.value:
            text = ctypes.string_at(err.value).decode("utf-8", "replace")
            self.lib.macula_free_string(err.value)
            raise native_error(text)
        return result

    def call(self, name: str, *args: Any) -> Any:
        """name(*args) for a function with no err_out."""
        return getattr(self.lib, name)(*args)

    def take_string(self, address: int | None) -> str | None:
        """The string at address, freed; None for NULL."""
        if not address:
            return None
        try:
            return ctypes.string_at(address).decode("utf-8")
        finally:
            self.lib.macula_free_string(address)

    def take_bytes(self, address: int | None, length: int) -> bytes:
        """length bytes at address, freed; b"" for NULL."""
        if not address:
            return b""
        try:
            return ctypes.string_at(address, length)
        finally:
            self.lib.macula_free_bytes(address)


class _Cancels:
    """Cancel tokens, as _blocking.run_blocking takes them."""

    def __init__(self, lib: ctypes.CDLL) -> None:
        self._lib = lib

    def new(self) -> int:
        return self._lib.macula_cancel_new()

    def cancel(self, h: int) -> None:
        self._lib.macula_cancel(h)

    def free(self, h: int) -> None:
        self._lib.macula_cancel_free(h)


_native: Native | None = None
_lock = threading.Lock()


def native() -> Native:
    """The library, loaded on first use."""
    global _native
    with _lock:
        if _native is None:
            _native = Native(str(library_path()))
        return _native
