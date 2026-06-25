# Copyright 2026 J Code
# SPDX-License-Identifier: Apache-2.0
import hashlib
import secrets
from typing import Union

def to_bytes(data: Union[str, bytes]) -> bytes:
    return data.encode('utf-8') if isinstance(data, str) else data

def to_str(data: bytes) -> str:
    return data.decode('utf-8') if isinstance(data, bytes) else data

def secure_bytes(size: int = 32) -> bytes:
    return secrets.token_bytes(size)

def validate_nonempty(data: Union[str, bytes], name: str = "data"):
    b = to_bytes(data)
    if len(b) == 0:
        raise ValueError(f"  Input {name} cannot be empty.")

def validate_key(key: str, pattern: str = ""):
    if not key:
        raise ValueError(f"  Key must not be empty for pattern '{pattern}'.")

def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError(f"  Length mismatch in XOR: {len(a)} vs {len(b)}")
    return bytes(x ^ y for x, y in zip(a, b))

def mac(key: bytes, data: bytes) -> bytes:
    return hashlib.blake2b(data, key=key, digest_size=32).digest()