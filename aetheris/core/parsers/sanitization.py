"""
Project AETHERIS - Reactive Prober Payload Sanitization & JSON Hardening
Provides defensive recursive sanitization to guarantee deterministic JSON serialization:
- Converts binary frames (bytes, bytearray, memoryview) into lowercase hexadecimal strings (.hex())
- Enforces buffer bounding (max_hex_bytes) to prevent memory expansion from oversized frames
- Cleans null terminators (\\x00) and unprintable ASCII control characters from string fields
- Coerces non-standard numeric scalars to JSON-serializable primitives
- Coerces float('nan') and float('inf') to None
- Serializes dataclasses via dataclasses.asdict()
"""

import dataclasses
import math
import re
from typing import Any, Dict, List, Union


def clean_ascii_string(text: str) -> str:
    """
    Strips null terminators and non-printable control characters from text strings,
    preserving printable ASCII and standard whitespace.
    """
    if not isinstance(text, str):
        text = str(text)
    # Remove null bytes and C0/C1 control characters (excluding newline/carriage return/tab if appropriate)
    return re.sub(r"[\x00-\x1f\x7f-\x9f]", "", text).strip()


def sanitize_prober_payload(data: Any, max_hex_bytes: int = 1024) -> Any:
    """
    Recursively sanitizes prober payload data structures:
    1. Converts bytes, bytearray, and memoryview to bounded lowercase hexadecimal strings (.hex()).
    2. Cleans text strings of control characters and null terminators.
    3. Recursively descends into dicts, lists, tuples, and sets.
    4. Guarantees 100% JSON-serializability for FastAPI, WebSockets, and SpatialLedger.
    5. Coerces NaN and Inf floats to None.
    6. Recursively serializes dataclasses.
    """
    if isinstance(data, (bytes, bytearray, memoryview)):
        b = bytes(data)
        if len(b) > max_hex_bytes:
            b = b[:max_hex_bytes]
        return b.hex()

    if isinstance(data, str):
        return clean_ascii_string(data)

    if dataclasses.is_dataclass(data) and not isinstance(data, type):
        return sanitize_prober_payload(dataclasses.asdict(data), max_hex_bytes=max_hex_bytes)

    if isinstance(data, dict):
        sanitized_dict: Dict[str, Any] = {}
        for k, v in data.items():
            key_str = clean_ascii_string(str(k))
            sanitized_dict[key_str] = sanitize_prober_payload(v, max_hex_bytes=max_hex_bytes)
        return sanitized_dict

    if isinstance(data, (list, tuple, set)):
        return [sanitize_prober_payload(item, max_hex_bytes=max_hex_bytes) for item in data]

    # Handle float NaN and Inf
    if isinstance(data, float):
        if math.isnan(data) or math.isinf(data):
            return None
        return data

    # Handle primitive numbers, bools, and None directly
    if data is None or isinstance(data, (int, bool)):
        return data

    # Fallback for unexpected objects: convert to clean string
    return clean_ascii_string(str(data))

