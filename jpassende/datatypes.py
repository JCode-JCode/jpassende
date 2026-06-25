# Copyright 2026 J Code
# SPDX-License-Identifier: Apache-2.0
from dataclasses import dataclass, field
from typing import Union
import time

@dataclass
class CryptoResult:
    encoded: Union[str, bytes]
    pattern: str
    layer: str
    needs_key: bool
    timestamp: float = field(default_factory=time.time)
    elapsed: float = 0.0

@dataclass
class DecodeResult:
    decoded: Union[str, bytes]
    pattern: str
    layer: str
    verified: bool
    elapsed: float = 0.0