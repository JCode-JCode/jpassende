# Copyright 2026 J Code
# SPDX-License-Identifier: Apache-2.0
import hashlib
import base64
import hmac
import struct
import time
import logging
import threading
from collections import OrderedDict
from typing import Union, Optional, List, Tuple

from Crypto.Protocol.KDF import PBKDF2, HKDF
from Crypto.Hash import SHA512, SHA256

from ._version import __version__
from .enums import SecurityLayer, PatternCategory
from .exceptions import InvalidPackageError
from .datatypes import CryptoResult, DecodeResult
from . import utils

from .mixins.aead import AeadMixin
from .mixins.stream import StreamMixin
from .mixins.block import BlockMixin
from .mixins.derivation import DerivationMixin

logger = logging.getLogger(__name__)


class JPassende(AeadMixin, StreamMixin, BlockMixin, DerivationMixin):
    PATTERNS = {
        'vail': {'category': PatternCategory.AEAD},
        'phnx': {'category': PatternCategory.AEAD},
        'nixl': {'category': PatternCategory.AEAD},
        'strx': {'category': PatternCategory.STREAM},
        'rvrs': {'category': PatternCategory.STREAM},
        'lfsr': {'category': PatternCategory.STREAM},
        'aegs': {'category': PatternCategory.BLOCK},
        'cblk': {'category': PatternCategory.BLOCK},
        'cfbb': {'category': PatternCategory.BLOCK},
        'ofbb': {'category': PatternCategory.BLOCK},
        'hkdf': {'category': PatternCategory.DERIVATION},
        'scrt': {'category': PatternCategory.DERIVATION},
        'pbk2': {'category': PatternCategory.DERIVATION},
        'blk3': {'category': PatternCategory.DERIVATION},
    }
    PATTERN_IDS = {
        'vail': 0, 'phnx': 1, 'nixl': 2, 'strx': 3,
        'rvrs': 4, 'lfsr': 5, 'aegs': 6, 'cblk': 7,
        'cfbb': 8, 'ofbb': 9, 'hkdf': 10, 'scrt': 11,
        'pbk2': 12, 'blk3': 13
    }
    PATTERN_INDEX = PATTERN_IDS

    def __init__(self, enable_logging: bool = False):
        if enable_logging:
            if not logger.handlers:
                handler = logging.StreamHandler()
                formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
                handler.setFormatter(formatter)
                logger.addHandler(handler)
                logger.setLevel(logging.DEBUG)
        else:
            logger.setLevel(logging.ERROR)

        self._salt_size = 32
        self._default_nonce = 12
        self._mac_size = 32
        self._MAGIC = b'jpas'
        self._VERSION = 1

        self._derive_cache: OrderedDict = OrderedDict()
        self._cache_lock = threading.Lock()
        self._max_cache_entries = 128

        self._encryptors = {
            'vail': self.vail, 'phnx': self.phnx, 'nixl': self.nixl,
            'strx': self.strx, 'rvrs': self.rvrs, 'lfsr': self.lfsr,
            'aegs': self.aegs, 'cblk': self.cblk, 'cfbb': self.cfbb, 'ofbb': self.ofbb,
            'hkdf': self.hkdf, 'scrt': self.scrt, 'pbk2': self.pbk2, 'blk3': self.blk3,
        }
        self._decryptors = {
            'vail': self.dvail, 'phnx': self.dphnx, 'nixl': self.dnixl,
            'strx': self.dstrx, 'rvrs': self.drvrs, 'lfsr': self.dlfsr,
            'aegs': self.daegs, 'cblk': self.dcblk, 'cfbb': self.dcfbb, 'ofbb': self.dofbb,
            'hkdf': self.dhkdf, 'scrt': self.dscrt, 'pbk2': self.dpbk2, 'blk3': self.dblk3,
        }

    @staticmethod
    def _to_bytes(data: Union[str, bytes]) -> bytes:
        return utils.to_bytes(data)

    @staticmethod
    def _to_str(data: bytes) -> str:
        return utils.to_str(data)

    @staticmethod
    def _secure_bytes(size: int = 32) -> bytes:
        return utils.secure_bytes(size)

    def _validate_nonempty(self, data: Union[str, bytes], name: str = "data"):
        utils.validate_nonempty(data, name)

    @staticmethod
    def _validate_key(key: str, pattern: str = ""):
        utils.validate_key(key, pattern)

    @staticmethod
    def _xor_bytes(a: bytes, b: bytes) -> bytes:
        return utils.xor_bytes(a, b)

    def _mac(self, key: bytes, data: bytes) -> bytes:
        return utils.mac(key, data)

    def _derive_key(self, password: str, salt: bytes, length: int = 32,
                    layer: SecurityLayer = SecurityLayer.STANDARD) -> bytes:
        hash_input = password.encode() + salt + struct.pack('>IB', length, layer.value)
        cache_key = hashlib.blake2b(hash_input, digest_size=16).digest()
        with self._cache_lock:
            if cache_key in self._derive_cache:
                self._derive_cache.move_to_end(cache_key)
                logger.debug("Cache hit for key derivation")
                return self._derive_cache[cache_key]
        iterations = {
            SecurityLayer.STANDARD: 300_000,
            SecurityLayer.FORTIFIED: 600_000,
            SecurityLayer.QUANTUM: 1_200_000
        }
        logger.debug("Deriving key with PBKDF2 (iterations=%d)", iterations[layer])
        derived = PBKDF2(password.encode(), salt, dkLen=length,
                         count=iterations[layer], hmac_hash_module=SHA512)
        with self._cache_lock:
            if len(self._derive_cache) >= self._max_cache_entries:
                self._derive_cache.popitem(last=False)
            self._derive_cache[cache_key] = derived
        return derived

    def _derive_keys(self, key: str, salt: bytes, layer: SecurityLayer) -> Tuple[bytes, bytes]:
        base_key = self._derive_key(key, salt, 32, layer)
        material = HKDF(base_key, 64, salt, SHA256, context=b'jpassende:keys:v2')
        return material[:32], material[32:]

    def _nonce_size_for(self, pattern: str) -> int:
        """Return expected nonce size for a given pattern (bytes)."""
        if pattern in ('vail', 'phnx', 'nixl'):
            return 12
        if pattern in ('aegs', 'cblk', 'cfbb', 'ofbb'):
            return 16
        if pattern in ('strx', 'rvrs', 'lfsr'):
            return 16
        if pattern in ('hkdf', 'scrt', 'pbk2', 'blk3'):
            return 0
        return self._default_nonce

    # ---- pack/unpack helpers ----
    def _pack(self, pattern: str, aad: Optional[bytes], salt: bytes,
              nonce: bytes, ciphertext: bytes, mac_key: Optional[bytes] = None) -> bytes:
        pattern_id = self.PATTERN_INDEX[pattern]
        flags = 0x01 if aad else 0
        header = self._MAGIC + bytes([self._VERSION, pattern_id, flags])
        payload = header
        if aad:
            aad_block = struct.pack('>I', len(aad)) + aad
            payload += aad_block
        body = salt + nonce + ciphertext
        payload += body
        if mac_key:
            payload += self._mac(mac_key, payload)
        return payload

    def _unpack(self, encoded: bytes, pattern: str) -> Tuple[Optional[bytes], bytes, bytes, bytes, Optional[bytes]]:
        if len(encoded) < 7:
            raise InvalidPackageError("  Invalid package – too short for header")
        if encoded[:4] != self._MAGIC:
            raise InvalidPackageError("  Invalid magic bytes")
        if encoded[4] != self._VERSION:
            raise InvalidPackageError(f"  Unsupported version: {encoded[4]}")
        if encoded[5] != self.PATTERN_INDEX[pattern]:
            raise InvalidPackageError("  Pattern mismatch")
        flags = encoded[6]
        pos = 7
        aad = None
        if flags & 0x01:
            if len(encoded) < pos + 4:
                raise InvalidPackageError("  Invalid package – missing AAD length")
            aad_len = struct.unpack('>I', encoded[pos:pos + 4])[0]
            pos += 4
            if len(encoded) < pos + aad_len:
                raise InvalidPackageError("  Invalid package – truncated AAD")
            aad = encoded[pos:pos + aad_len]
            pos += aad_len
        salt_size = self._salt_size
        nonce_size = self._nonce_size_for(pattern)
        mac_size = 0 if pattern in ('vail', 'phnx') else self._mac_size
        total_body = len(encoded) - pos
        if total_body < salt_size + nonce_size + mac_size:
            raise InvalidPackageError("  Invalid package – body too short")
        salt = encoded[pos:pos + salt_size]
        pos += salt_size
        nonce = encoded[pos:pos + nonce_size] if nonce_size > 0 else b''
        pos += nonce_size
        ciphertext_len = total_body - salt_size - nonce_size - mac_size
        ciphertext = encoded[pos:pos + ciphertext_len]
        pos += ciphertext_len
        mac_val = encoded[pos:pos + mac_size] if mac_size > 0 else None
        pos += mac_size if mac_size > 0 else 0

        if pos != len(encoded):
            raise InvalidPackageError("  Invalid package – trailing data after payload")
        return aad, salt, nonce, ciphertext, mac_val

    def _pack_derivation(self, pattern: str, aad: Optional[bytes],
                         salt: bytes, derived_data: bytes, verification: bytes) -> bytes:
        pattern_id = self.PATTERN_INDEX[pattern]
        flags = 0x01 if aad else 0
        header = self._MAGIC + bytes([self._VERSION, pattern_id, flags])
        aad_block = struct.pack('>I', len(aad)) + aad if aad else b''
        return header + aad_block + salt + derived_data + verification

    def _unpack_derivation(self, package: bytes, pattern: str) -> Tuple[Optional[bytes], bytes, bytes, bytes]:
        if package[:4] != self._MAGIC or package[4] != self._VERSION or package[5] != self.PATTERN_INDEX[pattern]:
            raise InvalidPackageError("  Header mismatch")
        flags = package[6]
        pos = 7
        aad = None
        if flags & 0x01:
            if len(package) < pos + 4:
                raise InvalidPackageError("  Invalid package – missing AAD length")
            aad_len = struct.unpack('>I', package[pos:pos + 4])[0]
            pos += 4
            if len(package) < pos + aad_len:
                raise InvalidPackageError("  Invalid package – truncated AAD")
            aad = package[pos:pos + aad_len]
            pos += aad_len
        salt = package[pos:pos + self._salt_size]
        pos += self._salt_size
        derived = package[pos:-16]
        verification = package[-16:]
        if pos + len(derived) + 16 != len(package):
            raise InvalidPackageError("  Invalid derivation package – trailing data")
        return aad, salt, derived, verification

    def encode(self, data: Union[str, bytes], pattern: str, key: str = "",
               layer: SecurityLayer = SecurityLayer.STANDARD,
               aad: Optional[bytes] = None,
               output_raw: bool = False, input_raw: bool = False,
               **kwargs) -> CryptoResult:
        if pattern not in self.PATTERNS:
            raise ValueError(f"  Unknown pattern: {pattern}")
        encryptor = self._encryptors[pattern]
        t0 = time.perf_counter()
        encoded = encryptor(data, key, aad=aad, layer=layer,
                            output_raw=output_raw, input_raw=input_raw, **kwargs)
        elapsed = time.perf_counter() - t0
        return CryptoResult(encoded=encoded, pattern=pattern, layer=layer.name,
                            needs_key=bool(key), elapsed=elapsed)

    def decode(self, encoded: Union[str, bytes], pattern: str, key: str = "",
               layer: SecurityLayer = SecurityLayer.STANDARD,
               aad: Optional[bytes] = None,
               output_raw: bool = False, input_raw: bool = False,
               **kwargs) -> DecodeResult:
        if pattern not in self.PATTERNS:
            raise ValueError(f"  Unknown pattern: {pattern}")
        decryptor = self._decryptors[pattern]
        t0 = time.perf_counter()
        decoded = decryptor(encoded, key, aad=aad, layer=layer,
                            output_raw=output_raw, input_raw=input_raw, **kwargs)
        elapsed = time.perf_counter() - t0
        return DecodeResult(decoded=decoded, pattern=pattern, layer=layer.name,
                            verified=True, elapsed=elapsed)

    def list_patterns(self) -> List[str]:
        return list(self.PATTERNS.keys())