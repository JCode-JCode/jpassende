# Copyright 2026 J Code
# SPDX-License-Identifier: Apache-2.0
import hashlib
import hmac
import base64
import struct
import logging
from typing import Union, Optional
from Crypto.Protocol.KDF import PBKDF2, scrypt, HKDF
from Crypto.Hash import SHA512, SHA256
from ..enums import SecurityLayer

logger = logging.getLogger(__name__)

class DerivationMixin:
    def hkdf(self, data: Union[str, bytes], key: str, length: int = 64,
             aad: Optional[bytes] = None, layer: SecurityLayer = SecurityLayer.STANDARD,
             output_raw: bool = False, input_raw: bool = False) -> Union[str, bytes]:
        if input_raw:
            data_bytes = data if isinstance(data, bytes) else data.encode('utf-8')
        else:
            self._validate_nonempty(data)
            data_bytes = self._to_bytes(data)
        self._validate_key(key, 'hkdf')
        max_len = 255 * hashlib.sha512().digest_size
        if length > max_len:
            raise ValueError(f"  Requested HKDF output length ({length}) exceeds maximum allowed ({max_len})")
        salt = self._secure_bytes(self._salt_size)
        key_bytes = self._derive_key(key, salt, 32, layer)
        derived = HKDF(data_bytes, length, salt, SHA512, context=b'jpassende:hkdf:v1')
        verification = hashlib.blake2b(derived + key_bytes, digest_size=16).digest()
        package = self._pack_derivation('hkdf', aad, salt, derived, verification)
        logger.debug("hkdf: derived %d bytes", len(derived))
        return package if output_raw else base64.b85encode(package).decode('utf-8')

    def dhkdf(self, encoded, key, length=64, aad=None, layer=SecurityLayer.STANDARD,
              output_raw=False, input_raw=False):
        if input_raw:
            package = encoded if isinstance(encoded, bytes) else encoded.encode('utf-8')
        else:
            if not encoded:
                raise ValueError("  Encoded data cannot be empty.")
            package = encoded if isinstance(encoded, bytes) else base64.b85decode(encoded.encode('utf-8'))
        self._validate_key(key, 'dhkdf')
        aad_pkg, salt, derived, verification = self._unpack_derivation(package, 'hkdf')
        if aad is not None and aad != aad_pkg:
            raise ValueError("  AAD mismatch")
        key_bytes = self._derive_key(key, salt, 32, layer)
        expected = hashlib.blake2b(derived + key_bytes, digest_size=16).digest()
        if not hmac.compare_digest(verification, expected):
            raise ValueError("  Verification failed")
        logger.debug("dhkdf: verified %d bytes", len(derived))
        return derived if output_raw else derived.hex()

    def scrt(self, data, key, aad=None, layer=SecurityLayer.STANDARD,
             output_raw=False, input_raw=False):
        if input_raw:
            data_bytes = data if isinstance(data, bytes) else data.encode('utf-8')
        else:
            self._validate_nonempty(data)
            data_bytes = self._to_bytes(data)
        self._validate_key(key, 'scrt')
        salt = self._secure_bytes(self._salt_size)
        key_bytes = self._derive_key(key, salt, 32, layer)
        n = {SecurityLayer.STANDARD: 2**14, SecurityLayer.FORTIFIED: 2**17, SecurityLayer.QUANTUM: 2**20}[layer]
        derived = scrypt(data_bytes, salt, key_len=64, N=n, r=8, p=1)
        verification = hmac.digest(key_bytes, derived, hashlib.sha3_512)[:16]
        package = self._pack_derivation('scrt', aad, salt, derived, verification)
        logger.debug("scrt: derived %d bytes", len(derived))
        return package if output_raw else base64.b85encode(package).decode('utf-8')

    def dscrt(self, encoded, key, aad=None, layer=SecurityLayer.STANDARD,
              output_raw=False, input_raw=False):
        if input_raw:
            package = encoded if isinstance(encoded, bytes) else encoded.encode('utf-8')
        else:
            if not encoded:
                raise ValueError("  Encoded data cannot be empty.")
            package = encoded if isinstance(encoded, bytes) else base64.b85decode(encoded.encode('utf-8'))
        self._validate_key(key, 'dscrt')
        aad_pkg, salt, derived, verification = self._unpack_derivation(package, 'scrt')
        if aad is not None and aad != aad_pkg:
            raise ValueError("  AAD mismatch")
        key_bytes = self._derive_key(key, salt, 32, layer)
        expected = hmac.digest(key_bytes, derived, hashlib.sha3_512)[:16]
        if not hmac.compare_digest(verification, expected):
            raise ValueError("  Verification failed")
        logger.debug("dscrt: verified %d bytes", len(derived))
        return derived if output_raw else derived.hex()

    def pbk2(self, data, key, aad=None, layer=SecurityLayer.STANDARD,
             output_raw=False, input_raw=False):
        if input_raw:
            data_bytes = data if isinstance(data, bytes) else data.encode('utf-8')
        else:
            self._validate_nonempty(data)
            data_bytes = self._to_bytes(data)
        self._validate_key(key, 'pbk2')
        salt = self._secure_bytes(self._salt_size)
        iterations = {SecurityLayer.STANDARD: 300_000, SecurityLayer.FORTIFIED: 600_000,
                      SecurityLayer.QUANTUM: 1_200_000}[layer]
        derived = PBKDF2(data_bytes, salt, dkLen=64, count=iterations, hmac_hash_module=SHA512)
        key_bytes = self._derive_key(key, salt, 32, layer)
        verification = hmac.digest(key_bytes, derived, hashlib.blake2s)[:16]
        package = self._pack_derivation('pbk2', aad, salt, derived, verification)
        logger.debug("pbk2: derived %d bytes", len(derived))
        return package if output_raw else base64.b85encode(package).decode('utf-8')

    def dpbk2(self, encoded, key, aad=None, layer=SecurityLayer.STANDARD,
              output_raw=False, input_raw=False):
        if input_raw:
            package = encoded if isinstance(encoded, bytes) else encoded.encode('utf-8')
        else:
            if not encoded:
                raise ValueError("  Encoded data cannot be empty.")
            package = encoded if isinstance(encoded, bytes) else base64.b85decode(encoded.encode('utf-8'))
        self._validate_key(key, 'dpbk2')
        aad_pkg, salt, derived, verification = self._unpack_derivation(package, 'pbk2')
        if aad is not None and aad != aad_pkg:
            raise ValueError("  AAD mismatch")
        key_bytes = self._derive_key(key, salt, 32, layer)
        expected = hmac.digest(key_bytes, derived, hashlib.blake2s)[:16]
        if not hmac.compare_digest(verification, expected):
            raise ValueError("  Verification failed")
        logger.debug("dpbk2: verified %d bytes", len(derived))
        return derived if output_raw else derived.hex()

    def blk3(self, data, key, aad=None, layer=SecurityLayer.STANDARD,
             output_raw=False, input_raw=False):
        if input_raw:
            data_bytes = data if isinstance(data, bytes) else data.encode('utf-8')
        else:
            self._validate_nonempty(data)
            data_bytes = self._to_bytes(data)
        self._validate_key(key, 'blk3')
        salt = self._secure_bytes(self._salt_size)
        key_bytes = self._derive_key(key, salt, 32, layer)
        blocks = [data_bytes[i:i+64] for i in range(0, len(data_bytes), 64)]
        tree = [hashlib.blake2b(block + key_bytes, digest_size=32).digest() for block in blocks]
        while len(tree) > 1:
            new_level = []
            for i in range(0, len(tree), 2):
                combined = tree[i] + (tree[i+1] if i+1 < len(tree) else tree[i])
                new_level.append(hashlib.blake2b(combined + key_bytes, digest_size=32).digest())
            tree = new_level
        root = tree[0] if tree else hashlib.blake2b(key_bytes, digest_size=32).digest()
        verification = hmac.digest(key_bytes, root + salt, hashlib.sha3_256)[:16]
        package = self._pack_derivation('blk3', aad, salt, root, verification)
        logger.debug("blk3: root commitment %d bytes", len(root))
        return package if output_raw else base64.b85encode(package).decode('utf-8')

    def dblk3(self, encoded, key, aad=None, layer=SecurityLayer.STANDARD,
              output_raw=False, input_raw=False):
        if input_raw:
            package = encoded if isinstance(encoded, bytes) else encoded.encode('utf-8')
        else:
            if not encoded:
                raise ValueError("  Encoded data cannot be empty.")
            package = encoded if isinstance(encoded, bytes) else base64.b85decode(encoded.encode('utf-8'))
        self._validate_key(key, 'dblk3')
        aad_pkg, salt, root, verification = self._unpack_derivation(package, 'blk3')
        if aad is not None and aad != aad_pkg:
            raise ValueError("  AAD mismatch")
        key_bytes = self._derive_key(key, salt, 32, layer)
        expected = hmac.digest(key_bytes, root + salt, hashlib.sha3_256)[:16]
        if not hmac.compare_digest(verification, expected):
            raise ValueError("  Verification failed")
        logger.debug("dblk3: verified root %d bytes", len(root))
        return root if output_raw else root.hex()