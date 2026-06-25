# Copyright 2026 J Code
# SPDX-License-Identifier: Apache-2.0
import hashlib
import base64
import hmac
import logging
from typing import Union, Optional
from ..enums import SecurityLayer

logger = logging.getLogger(__name__)

class StreamMixin:
    def strx(self, data: Union[str, bytes], key: str, aad: Optional[bytes] = None,
             layer: SecurityLayer = SecurityLayer.STANDARD,
             output_raw: bool = False, input_raw: bool = False) -> Union[str, bytes]:
        if input_raw:
            data_bytes = data if isinstance(data, bytes) else data.encode('utf-8')
        else:
            self._validate_nonempty(data)
            data_bytes = self._to_bytes(data)
        self._validate_key(key, 'strx')
        salt = self._secure_bytes(self._salt_size)
        enc_key, mac_key = self._derive_keys(key, salt, layer)
        nonce = self._secure_bytes(16)
        blake2b = hashlib.blake2b
        xor = self._xor_bytes
        result = bytearray()
        counter = 0
        dlen = len(data_bytes)
        for i in range(0, dlen, 64):
            chunk = data_bytes[i:i + 64]
            keystream = blake2b(nonce + counter.to_bytes(16, 'little'),
                                key=enc_key, digest_size=64).digest()
            result.extend(xor(chunk, keystream[:len(chunk)]))
            counter += 1
        ciphertext = bytes(result)
        package = self._pack('strx', aad, salt, nonce, ciphertext, mac_key=mac_key)
        logger.debug("strx: encrypted %d bytes", len(ciphertext))
        return package if output_raw else base64.b85encode(package).decode('utf-8')

    def dstrx(self, encoded: Union[str, bytes], key: str, aad: Optional[bytes] = None,
              layer: SecurityLayer = SecurityLayer.STANDARD,
              output_raw: bool = False, input_raw: bool = False) -> Union[str, bytes]:
        if input_raw:
            package = encoded if isinstance(encoded, bytes) else encoded.encode('utf-8')
        else:
            if not encoded:
                raise ValueError("  Encoded data cannot be empty.")
            package = encoded if isinstance(encoded, bytes) else base64.b85decode(encoded.encode('utf-8'))
        self._validate_key(key, 'dstrx')
        aad_pkg, salt, nonce, ciphertext, mac_val = self._unpack(package, 'strx')
        if aad is not None and aad != aad_pkg:
            raise ValueError("  AAD mismatch")
        enc_key, mac_key = self._derive_keys(key, salt, layer)
        to_verify = package[:-len(mac_val)] if mac_val else package
        if mac_val and not hmac.compare_digest(mac_val, self._mac(mac_key, to_verify)):
            raise ValueError("  MAC verification failed")
        blake2b = hashlib.blake2b
        xor = self._xor_bytes
        result = bytearray()
        counter = 0
        clen = len(ciphertext)
        for i in range(0, clen, 64):
            chunk = ciphertext[i:i + 64]
            keystream = blake2b(nonce + counter.to_bytes(16, 'little'),
                                key=enc_key, digest_size=64).digest()
            result.extend(xor(chunk, keystream[:len(chunk)]))
            counter += 1
        plain = bytes(result)
        logger.debug("dstrx: decrypted %d bytes", len(plain))
        return plain if output_raw else self._to_str(plain)

    def rvrs(self, data, key, aad=None, layer=SecurityLayer.STANDARD,
             output_raw=False, input_raw=False):
        if input_raw:
            data_bytes = data if isinstance(data, bytes) else data.encode('utf-8')
        else:
            self._validate_nonempty(data)
            data_bytes = self._to_bytes(data)
        self._validate_key(key, 'rvrs')
        salt = self._secure_bytes(self._salt_size)
        enc_key, mac_key = self._derive_keys(key, salt, layer)
        nonce = self._secure_bytes(16)
        block_size = 32
        sha3 = hashlib.sha3_256
        xor = self._xor_bytes
        result = bytearray()
        prev = nonce
        dlen = len(data_bytes)
        for i in range(0, dlen, block_size):
            chunk = data_bytes[i:i + block_size]
            keystream = sha3(enc_key + prev).digest()[:len(chunk)]
            cipher_chunk = xor(chunk, keystream)
            result.extend(cipher_chunk)
            prev = cipher_chunk
        ciphertext = bytes(result)
        package = self._pack('rvrs', aad, salt, nonce, ciphertext, mac_key=mac_key)
        logger.debug("rvrs: encrypted %d bytes", len(ciphertext))
        return package if output_raw else base64.b85encode(package).decode('utf-8')

    def drvrs(self, encoded, key, aad=None, layer=SecurityLayer.STANDARD,
              output_raw=False, input_raw=False):
        if input_raw:
            package = encoded if isinstance(encoded, bytes) else encoded.encode('utf-8')
        else:
            if not encoded:
                raise ValueError("  Encoded data cannot be empty.")
            package = encoded if isinstance(encoded, bytes) else base64.b85decode(encoded.encode('utf-8'))
        self._validate_key(key, 'drvrs')
        aad_pkg, salt, nonce, ciphertext, mac_val = self._unpack(package, 'rvrs')
        if aad is not None and aad != aad_pkg:
            raise ValueError("  AAD mismatch")
        enc_key, mac_key = self._derive_keys(key, salt, layer)
        to_verify = package[:-len(mac_val)] if mac_val else package
        if mac_val and not hmac.compare_digest(mac_val, self._mac(mac_key, to_verify)):
            raise ValueError("  MAC verification failed")
        block_size = 32
        sha3 = hashlib.sha3_256
        xor = self._xor_bytes
        result = bytearray()
        prev = nonce
        clen = len(ciphertext)
        for i in range(0, clen, block_size):
            chunk = ciphertext[i:i + block_size]
            keystream = sha3(enc_key + prev).digest()[:len(chunk)]
            plain_chunk = xor(chunk, keystream)
            result.extend(plain_chunk)
            prev = chunk
        plain = bytes(result)
        logger.debug("drvrs: decrypted %d bytes", len(plain))
        return plain if output_raw else self._to_str(plain)

    def lfsr(self, data, key, aad=None, layer=SecurityLayer.STANDARD,
             output_raw=False, input_raw=False):
        if input_raw:
            data_bytes = data if isinstance(data, bytes) else data.encode('utf-8')
        else:
            self._validate_nonempty(data)
            data_bytes = self._to_bytes(data)
        self._validate_key(key, 'lfsr')
        salt = self._secure_bytes(self._salt_size)
        enc_key, mac_key = self._derive_keys(key, salt, layer)
        nonce = self._secure_bytes(16)
        sha3 = hashlib.sha3_256
        blake2b = hashlib.blake2b
        stateA = sha3(enc_key + nonce).digest()
        stateB = blake2b(enc_key + nonce, digest_size=32).digest()
        result = bytearray()
        for byte in data_bytes:
            result.append(byte ^ (stateA[0] ^ stateB[0]))
            stateA = sha3(stateA).digest()
            stateB = blake2b(stateB, digest_size=32).digest()
        ciphertext = bytes(result)
        package = self._pack('lfsr', aad, salt, nonce, ciphertext, mac_key=mac_key)
        logger.debug("lfsr: encrypted %d bytes", len(ciphertext))
        return package if output_raw else base64.b85encode(package).decode('utf-8')

    def dlfsr(self, encoded, key, aad=None, layer=SecurityLayer.STANDARD,
              output_raw=False, input_raw=False):
        if input_raw:
            package = encoded if isinstance(encoded, bytes) else encoded.encode('utf-8')
        else:
            if not encoded:
                raise ValueError("  Encoded data cannot be empty.")
            package = encoded if isinstance(encoded, bytes) else base64.b85decode(encoded.encode('utf-8'))
        self._validate_key(key, 'dlfsr')
        aad_pkg, salt, nonce, ciphertext, mac_val = self._unpack(package, 'lfsr')
        if aad is not None and aad != aad_pkg:
            raise ValueError("  AAD mismatch")
        enc_key, mac_key = self._derive_keys(key, salt, layer)
        to_verify = package[:-len(mac_val)] if mac_val else package
        if mac_val and not hmac.compare_digest(mac_val, self._mac(mac_key, to_verify)):
            raise ValueError("  MAC verification failed")
        sha3 = hashlib.sha3_256
        blake2b = hashlib.blake2b
        stateA = sha3(enc_key + nonce).digest()
        stateB = blake2b(enc_key + nonce, digest_size=32).digest()
        result = bytearray()
        for byte in ciphertext:
            result.append(byte ^ (stateA[0] ^ stateB[0]))
            stateA = sha3(stateA).digest()
            stateB = blake2b(stateB, digest_size=32).digest()
        plain = bytes(result)
        logger.debug("dlfsr: decrypted %d bytes", len(plain))
        return plain if output_raw else self._to_str(plain)