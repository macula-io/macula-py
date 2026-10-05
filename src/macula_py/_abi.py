"""macula-go's C ABI (abi/macula.h), declared for ctypes.

Types are written as the header writes them, so tests/test_abi_declarations.py
can hold this table to the header function for function; _native maps them to
ctypes. Returned strings and byte buffers are declared as pointers (never
c_char_p) so they can be freed with macula_free_string / macula_free_bytes.
"""

from __future__ import annotations

ABI_VERSION = 1
# The oldest macula-go release this macula-py supports: its library exports
# every function below (a new function does not change ABI_VERSION):
# macula_signed_object_verify since v0.22.0. It speaks handshake v5 (the
# channel binding, v0.20.0) and offers SecP384r1MLKEM1024 alone (v0.23.0,
# macula-go#20), which an older library would silently lack: it would land on
# SecP256r1MLKEM768 with every station.
LIBRARY_FLOOR = "v0.23.0"

H = "macula_handle"
ERR = "char**"
REALM = "const uint8_t*"

FUNCTIONS: dict[str, tuple[str, list[str]]] = {
    # The library
    "macula_abi_version": ("int32_t", []),
    "macula_free_string": ("void", ["char*"]),
    "macula_free_bytes": ("void", ["uint8_t*"]),
    # Cancellation
    "macula_cancel_new": (H, []),
    "macula_cancel": ("void", [H]),
    "macula_cancel_free": ("void", [H]),
    # Node keys
    "macula_key_generate": (H, ["const char*", H, ERR]),
    "macula_key_load": (H, ["const char*", "const char*", ERR]),
    "macula_key_load_or_create": (H, ["const char*", "const char*", H, ERR]),
    "macula_key_save": ("void", [H, "const char*", ERR]),
    "macula_key_node_id": ("void", [H, "uint8_t*", ERR]),
    "macula_key_public_key": ("uint8_t*", [H, "size_t*", ERR]),
    "macula_key_profile": ("char*", [H, ERR]),
    "macula_key_sign": ("uint8_t*", [H, "const uint8_t*", "size_t", "size_t*", ERR]),
    "macula_verify": (
        "int32_t",
        ["const uint8_t*", "size_t", "const uint8_t*", "size_t", "const uint8_t*", "size_t", "const char*", ERR],
    ),
    "macula_key_free": ("void", [H]),
    # Device request proofs (realm proof v2)
    "macula_key_device_request_proof": ("char*", [H, REALM, "const char*", "const char*", "int32_t", ERR]),
    "macula_device_request_message": (
        "uint8_t*",
        ["const uint8_t*", "size_t", REALM, "const char*", "int64_t", "const uint8_t*", "const char*", "int32_t",
         "size_t*", ERR],
    ),
    # Ownership proofs (v2)
    "macula_key_ownership_proof": ("char*", [H, REALM, "const char*", "const char*", ERR]),
    "macula_ownership_proof_message": (
        "uint8_t*",
        ["const uint8_t*", REALM, "const char*", "int64_t", "const uint8_t*", "const char*", "size_t*", ERR],
    ),
    # UCANs
    "macula_ucan_create": ("char*", [H, "const uint8_t*", "const char*", "int64_t", "const char*", ERR]),
    "macula_ucan_proof_id": ("char*", ["const char*", ERR]),
    # Signed objects. Declared because the header has it; the Python API does not use it yet.
    "macula_signed_object_verify": ("char*", ["const char*", "const uint8_t*", "size_t", "const char*", ERR]),
    # Pool
    "macula_pool_connect": (H, [H, "const char*", "const char*", H, ERR]),
    "macula_pool_close": ("void", [H]),
    "macula_pool_node_id": ("void", [H, "uint8_t*", ERR]),
    "macula_pool_status": ("char*", [H, ERR]),
    "macula_pool_events_next": ("char*", [H, "int64_t", H, "int32_t*", ERR]),
    # Calls. The Python API calls, serves and opens through the *_opts functions, whose options carry a UCAN,
    # its proofs and the confidentiality in one set; the others are declared because the header has them.
    "macula_pool_call": ("char*", [H, REALM, "const char*", "const char*", "const uint8_t*", "int64_t", H, ERR]),
    "macula_pool_call_with": (
        "char*",
        [H, REALM, "const char*", "const char*", "const uint8_t*", "const char*", "const char*", "int64_t", H, ERR],
    ),
    "macula_pool_call_opts": ("char*", [H, REALM, "const char*", "const char*", "const char*", "int64_t", H, ERR]),
    "macula_pool_providers": ("char*", [H, REALM, "const char*", "int64_t", H, ERR]),
    # Publish / subscribe
    "macula_pool_publish": ("void", [H, REALM, "const char*", "const char*", "int64_t", ERR]),
    "macula_pool_subscribe": (H, [H, REALM, "const char*", ERR]),
    "macula_subscription_next": ("char*", [H, "int64_t", H, "int32_t*", ERR]),
    "macula_subscription_dropped": ("uint64_t", [H, ERR]),
    "macula_subscription_stop": ("void", [H]),
    # Serving
    "macula_pool_serve": (H, [H, REALM, "const char*", ERR]),
    "macula_pool_serve_stream": (H, [H, REALM, "const char*", "int32_t", ERR]),
    "macula_pool_serve_gated": (H, [H, REALM, "const char*", "const char*", ERR]),
    "macula_pool_serve_stream_gated": (H, [H, REALM, "const char*", "int32_t", "const char*", ERR]),
    "macula_pool_serve_opts": (H, [H, REALM, "const char*", "const char*", ERR]),
    "macula_pool_serve_stream_opts": (H, [H, REALM, "const char*", "int32_t", "const char*", ERR]),
    "macula_served_next": ("char*", [H, "int64_t", H, "macula_handle*", "int32_t*", ERR]),
    "macula_pending_reply": ("void", [H, "const char*", ERR]),
    "macula_pending_error": ("void", [H, "const char*", ERR]),
    "macula_served_stop": ("void", [H, ERR]),
    # Streams
    "macula_pool_open_stream": (
        H,
        [H, REALM, "const char*", "int32_t", "const char*", "const uint8_t*", "int64_t", "int64_t", H, ERR],
    ),
    "macula_pool_open_stream_opts": (
        H,
        [H, REALM, "const char*", "int32_t", "const char*", "const char*", "int64_t", "int64_t", H, ERR],
    ),
    "macula_pool_open_stream_with": (
        H,
        [H, REALM, "const char*", "int32_t", "const char*", "const uint8_t*", "const char*", "const char*",
         "int64_t", "int64_t", H, ERR],
    ),
    "macula_stream_request": ("char*", [H, ERR]),
    "macula_stream_report": ("char*", [H, ERR]),
    "macula_stream_send_bytes": ("void", [H, "const uint8_t*", "size_t", ERR]),
    "macula_stream_send_json": ("void", [H, "const char*", ERR]),
    "macula_stream_close_send": ("void", [H, ERR]),
    "macula_stream_reply": ("void", [H, "const char*", ERR]),
    "macula_stream_abort": ("void", [H, "const char*", "const char*", ERR]),
    "macula_stream_close": ("void", [H, ERR]),
    "macula_stream_recv": ("char*", [H, "int64_t", H, ERR]),
    "macula_stream_free": ("void", [H]),
    # Content
    "macula_pool_share_content": (
        "void",
        [H, REALM, "const uint8_t*", "size_t", "const char*", "int64_t", H, "uint8_t*", ERR],
    ),
    "macula_pool_unshare_content": ("void", [H, REALM, "const uint8_t*", "int64_t", H, ERR]),
    "macula_pool_get_content": (
        "uint8_t*",
        [H, REALM, "const uint8_t*", "const char*", "int64_t", H, "size_t*", ERR],
    ),
    # DHT records
    "macula_pool_find_record": ("char*", [H, "const uint8_t*", "int64_t", H, ERR]),
    "macula_pool_find_records": ("char*", [H, "const uint8_t*", "int64_t", H, ERR]),
    "macula_pool_find_records_by_type": ("char*", [H, "int32_t", "int64_t", H, ERR]),
    "macula_pool_put_record": ("void", [H, "const uint8_t*", "size_t", "int64_t", H, ERR]),
}
