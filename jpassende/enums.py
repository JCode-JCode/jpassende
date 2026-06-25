# Copyright 2026 J Code
# SPDX-License-Identifier: Apache-2.0
from enum import Enum, auto

class SecurityLayer(Enum):
    STANDARD = auto()
    FORTIFIED = auto()
    QUANTUM = auto()

class PatternCategory(Enum):
    AEAD = auto()
    STREAM = auto()
    BLOCK = auto()
    DERIVATION = auto()