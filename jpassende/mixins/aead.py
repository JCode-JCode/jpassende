# Copyright 2026 J Code
# SPDX-License-Identifier: Apache-2.0
import base64
import logging
from typing import Union, Optional
from Crypto.Cipher import AES, ChaCha20, ChaCha20_Poly1305
import hmac

from ..enums import SecurityLayer

logger = logging.getLogger(__name__)

class AeadMixin:
    def vail(self, data: Union[str, bytes], key: str, aad: Optional[bytes] = None,
             layer: SecurityLayer = SecurityLayer.STANDARD,
             output_raw: bool = False, input_raw: bool = False) -> Union[str, bytes]:
        if input_raw:
            data_bytes = data if isinstance(data, bytes) else data.encode('utf-8')
        else:
            self._validate_nonempty(data)
            data_bytes = self._to_bytes(data)
        self._validate_key(key, 'vail')
        salt = self._secure_bytes(self._salt_size)
        key_bytes = self._derive_key(key, salt, 32, layer)
        nonce = self._secure_bytes(12)
        cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=nonce)
        if aad:
            cipher.update(aad)
        ct, tag = cipher.encrypt_and_digest(data_bytes)
        ct_tag = ct + tag
        package = self._pack('vail', aad, salt, nonce, ct_tag)
        logger.debug("vail: encrypted %d bytes", len(ct_tag))
        return package if output_raw else base64.b85encode(package).decode('utf-8')

    def dvail(self, encoded: Union[str, bytes], key: str, aad: Optional[bytes] = None,
              layer: SecurityLayer = SecurityLayer.STANDARD,
              output_raw: bool = False, input_raw: bool = False) -> Union[str, bytes]:
        if input_raw:
            package = encoded if isinstance(encoded, bytes) else encoded.encode('utf-8')
        else:
            if not encoded:
                raise ValueError("  Encoded data cannot be empty.")
            clean = encoded.strip() if isinstance(encoded, str) else encoded
            package = clean if isinstance(clean, bytes) else base64.b85decode(clean.encode('utf-8'))
        self._validate_key(key, 'dvail')
        aad_pkg, salt, nonce, ct_tag, _ = self._unpack(package, 'vail')
        if aad is not None and aad != aad_pkg:
            raise ValueError("  AAD mismatch")
        key_bytes = self._derive_key(key, salt, 32, layer)
        cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=nonce)
        if aad_pkg:
            cipher.update(aad_pkg)
        try:
            plain = cipher.decrypt_and_verify(ct_tag[:-16], ct_tag[-16:])
        except (ValueError, KeyError):
            raise ValueError("  GCM authentication failed")
        logger.debug("dvail: decrypted %d bytes", len(plain))
        return plain if output_raw else self._to_str(plain)

    def phnx(self, data, key, aad=None, layer=SecurityLayer.STANDARD,
             output_raw=False, input_raw=False):
        if input_raw:
            data_bytes = data if isinstance(data, bytes) else data.encode('utf-8')
        else:
            self._validate_nonempty(data)
            data_bytes = self._to_bytes(data)
        self._validate_key(key, 'phnx')
        salt = self._secure_bytes(self._salt_size)
        key_bytes = self._derive_key(key, salt, 32, layer)
        nonce = self._secure_bytes(12)
        cipher = ChaCha20_Poly1305.new(key=key_bytes, nonce=nonce)
        if aad:
            cipher.update(aad)
        ct, tag = cipher.encrypt_and_digest(data_bytes)
        ct_tag = ct + tag
        package = self._pack('phnx', aad, salt, nonce, ct_tag)
        logger.debug("phnx: encrypted %d bytes", len(ct_tag))
        return package if output_raw else base64.b85encode(package).decode('utf-8')

    def dphnx(self, encoded, key, aad=None, layer=SecurityLayer.STANDARD,
              output_raw=False, input_raw=False):
        if input_raw:
            package = encoded if isinstance(encoded, bytes) else encoded.encode('utf-8')
        else:
            if not encoded:
                raise ValueError("  Encoded data cannot be empty.")
            clean = encoded.strip() if isinstance(encoded, str) else encoded
            package = clean if isinstance(clean, bytes) else base64.b85decode(clean.encode('utf-8'))
        self._validate_key(key, 'dphnx')
        aad_pkg, salt, nonce, ct_tag, _ = self._unpack(package, 'phnx')
        if aad is not None and aad != aad_pkg:
            raise ValueError("  AAD mismatch")
        key_bytes = self._derive_key(key, salt, 32, layer)
        cipher = ChaCha20_Poly1305.new(key=key_bytes, nonce=nonce)
        if aad_pkg:
            cipher.update(aad_pkg)
        try:
            plain = cipher.decrypt_and_verify(ct_tag[:-16], ct_tag[-16:])
        except (ValueError, KeyError):
            raise ValueError("  Poly1305 authentication failed")
        logger.debug("dphnx: decrypted %d bytes", len(plain))
        return plain if output_raw else self._to_str(plain)

    def nixl(self, data, key, aad=None, layer=SecurityLayer.STANDARD,
             output_raw=False, input_raw=False):
        if input_raw:
            data_bytes = data if isinstance(data, bytes) else data.encode('utf-8')
        else:
            self._validate_nonempty(data)
            data_bytes = self._to_bytes(data)
        self._validate_key(key, 'nixl')
        salt = self._secure_bytes(self._salt_size)
        enc_key, mac_key = self._derive_keys(key, salt, layer)
        nonce = self._secure_bytes(12)            # 12 bytes – must match _nonce_size_for
        cipher = ChaCha20.new(key=enc_key, nonce=nonce)
        ct = cipher.encrypt(data_bytes)
        package = self._pack('nixl', aad, salt, nonce, ct, mac_key=mac_key)
        logger.debug("nixl: encrypted %d bytes", len(ct))
        return package if output_raw else base64.b85encode(package).decode('utf-8')

    def dnixl(self, encoded, key, aad=None, layer=SecurityLayer.STANDARD,
              output_raw=False, input_raw=False):
        if input_raw:
            package = encoded if isinstance(encoded, bytes) else encoded.encode('utf-8')
        else:
            if not encoded:
                raise ValueError("  Encoded data cannot be empty.")
            clean = encoded.strip() if isinstance(encoded, str) else encoded
            package = clean if isinstance(clean, bytes) else base64.b85decode(clean.encode('utf-8'))
        self._validate_key(key, 'dnixl')
        aad_pkg, salt, nonce, ciphertext, mac_val = self._unpack(package, 'nixl')
        if aad is not None and aad != aad_pkg:
            raise ValueError("  AAD mismatch")
        enc_key, mac_key = self._derive_keys(key, salt, layer)
        to_verify = package[:-len(mac_val)] if mac_val else package
        if mac_val and not hmac.compare_digest(mac_val, self._mac(mac_key, to_verify)):
            raise ValueError("  MAC verification failed")
        cipher = ChaCha20.new(key=enc_key, nonce=nonce)
        plain = cipher.decrypt(ciphertext)
        logger.debug("dnixl: decrypted %d bytes", len(plain))
        return plain if output_raw else self._to_str(plain)