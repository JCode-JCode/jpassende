# Copyright 2026 J Code
# SPDX-License-Identifier: Apache-2.0
import base64
import logging
from typing import Union, Optional
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hmac

from ..enums import SecurityLayer

logger = logging.getLogger(__name__)

class BlockMixin:
    def aegs(self, data: Union[str, bytes], key: str, aad: Optional[bytes] = None,
             layer: SecurityLayer = SecurityLayer.STANDARD,
             output_raw: bool = False, input_raw: bool = False) -> Union[str, bytes]:
        if input_raw:
            data_bytes = data if isinstance(data, bytes) else data.encode('utf-8')
        else:
            self._validate_nonempty(data)
            data_bytes = self._to_bytes(data)
        self._validate_key(key, 'aegs')
        salt = self._secure_bytes(self._salt_size)
        enc_key, mac_key = self._derive_keys(key, salt, layer)
        iv = self._secure_bytes(16)
        cipher = AES.new(enc_key, AES.MODE_CTR, nonce=b'', initial_value=iv)
        padded = pad(data_bytes, AES.block_size)
        ciphertext = cipher.encrypt(padded)
        package = self._pack('aegs', aad, salt, iv, ciphertext, mac_key=mac_key)
        logger.debug("aegs: encrypted %d bytes", len(ciphertext))
        return package if output_raw else base64.b64encode(package).decode('utf-8')

    def daegs(self, encoded: Union[str, bytes], key: str, aad: Optional[bytes] = None,
              layer: SecurityLayer = SecurityLayer.STANDARD,
              output_raw: bool = False, input_raw: bool = False) -> Union[str, bytes]:
        if input_raw:
            package = encoded if isinstance(encoded, bytes) else encoded.encode('utf-8')
        else:
            if not encoded:
                raise ValueError("  Encoded data cannot be empty.")
            package = encoded if isinstance(encoded, bytes) else base64.b64decode(encoded.encode('utf-8'))
        self._validate_key(key, 'daegs')
        aad_pkg, salt, iv, ciphertext, mac_val = self._unpack(package, 'aegs')
        if aad is not None and aad != aad_pkg:
            raise ValueError("  AAD mismatch")
        enc_key, mac_key = self._derive_keys(key, salt, layer)
        to_verify = package[:-len(mac_val)] if mac_val else package
        if mac_val and not hmac.compare_digest(mac_val, self._mac(mac_key, to_verify)):
            raise ValueError("  MAC verification failed")
        cipher = AES.new(enc_key, AES.MODE_CTR, nonce=b'', initial_value=iv)
        padded = cipher.decrypt(ciphertext)
        plain = unpad(padded, AES.block_size)
        logger.debug("daegs: decrypted %d bytes", len(plain))
        return plain if output_raw else self._to_str(plain)

    def cblk(self, data, key, aad=None, layer=SecurityLayer.STANDARD,
             output_raw=False, input_raw=False):
        if input_raw:
            data_bytes = data if isinstance(data, bytes) else data.encode('utf-8')
        else:
            self._validate_nonempty(data)
            data_bytes = self._to_bytes(data)
        self._validate_key(key, 'cblk')
        salt = self._secure_bytes(self._salt_size)
        enc_key, mac_key = self._derive_keys(key, salt, layer)
        iv = self._secure_bytes(16)
        cipher = AES.new(enc_key, AES.MODE_CBC, iv=iv)
        padded = pad(data_bytes, AES.block_size)
        ciphertext = cipher.encrypt(padded)
        package = self._pack('cblk', aad, salt, iv, ciphertext, mac_key=mac_key)
        logger.debug("cblk: encrypted %d bytes", len(ciphertext))
        return package if output_raw else base64.b64encode(package).decode('utf-8')

    def dcblk(self, encoded, key, aad=None, layer=SecurityLayer.STANDARD,
              output_raw=False, input_raw=False):
        if input_raw:
            package = encoded if isinstance(encoded, bytes) else encoded.encode('utf-8')
        else:
            if not encoded:
                raise ValueError("  Encoded data cannot be empty.")
            package = encoded if isinstance(encoded, bytes) else base64.b64decode(encoded.encode('utf-8'))
        self._validate_key(key, 'dcblk')
        aad_pkg, salt, iv, ciphertext, mac_val = self._unpack(package, 'cblk')
        if aad is not None and aad != aad_pkg:
            raise ValueError("  AAD mismatch")
        enc_key, mac_key = self._derive_keys(key, salt, layer)
        to_verify = package[:-len(mac_val)] if mac_val else package
        if mac_val and not hmac.compare_digest(mac_val, self._mac(mac_key, to_verify)):
            raise ValueError("  MAC verification failed")
        cipher = AES.new(enc_key, AES.MODE_CBC, iv=iv)
        padded = cipher.decrypt(ciphertext)
        plain = unpad(padded, AES.block_size)
        logger.debug("dcblk: decrypted %d bytes", len(plain))
        return plain if output_raw else self._to_str(plain)

    def cfbb(self, data, key, aad=None, layer=SecurityLayer.STANDARD,
             output_raw=False, input_raw=False):
        if input_raw:
            data_bytes = data if isinstance(data, bytes) else data.encode('utf-8')
        else:
            self._validate_nonempty(data)
            data_bytes = self._to_bytes(data)
        self._validate_key(key, 'cfbb')
        salt = self._secure_bytes(self._salt_size)
        enc_key, mac_key = self._derive_keys(key, salt, layer)
        iv = self._secure_bytes(16)
        cipher = AES.new(enc_key, AES.MODE_CFB, iv=iv, segment_size=128)
        ciphertext = cipher.encrypt(data_bytes)
        package = self._pack('cfbb', aad, salt, iv, ciphertext, mac_key=mac_key)
        logger.debug("cfbb: encrypted %d bytes", len(ciphertext))
        return package if output_raw else base64.b64encode(package).decode('utf-8')

    def dcfbb(self, encoded, key, aad=None, layer=SecurityLayer.STANDARD,
              output_raw=False, input_raw=False):
        if input_raw:
            package = encoded if isinstance(encoded, bytes) else encoded.encode('utf-8')
        else:
            if not encoded:
                raise ValueError("  Encoded data cannot be empty.")
            package = encoded if isinstance(encoded, bytes) else base64.b64decode(encoded.encode('utf-8'))
        self._validate_key(key, 'dcfbb')
        aad_pkg, salt, iv, ciphertext, mac_val = self._unpack(package, 'cfbb')
        if aad is not None and aad != aad_pkg:
            raise ValueError("  AAD mismatch")
        enc_key, mac_key = self._derive_keys(key, salt, layer)
        to_verify = package[:-len(mac_val)] if mac_val else package
        if mac_val and not hmac.compare_digest(mac_val, self._mac(mac_key, to_verify)):
            raise ValueError("  MAC verification failed")
        cipher = AES.new(enc_key, AES.MODE_CFB, iv=iv, segment_size=128)
        plain = cipher.decrypt(ciphertext)
        logger.debug("dcfbb: decrypted %d bytes", len(plain))
        return plain if output_raw else self._to_str(plain)

    def ofbb(self, data, key, aad=None, layer=SecurityLayer.STANDARD,
             output_raw=False, input_raw=False):
        if input_raw:
            data_bytes = data if isinstance(data, bytes) else data.encode('utf-8')
        else:
            self._validate_nonempty(data)
            data_bytes = self._to_bytes(data)
        self._validate_key(key, 'ofbb')
        salt = self._secure_bytes(self._salt_size)
        enc_key, mac_key = self._derive_keys(key, salt, layer)
        iv = self._secure_bytes(16)
        cipher = AES.new(enc_key, AES.MODE_OFB, iv=iv)
        ciphertext = cipher.encrypt(data_bytes)
        package = self._pack('ofbb', aad, salt, iv, ciphertext, mac_key=mac_key)
        logger.debug("ofbb: encrypted %d bytes", len(ciphertext))
        return package if output_raw else base64.b64encode(package).decode('utf-8')

    def dofbb(self, encoded, key, aad=None, layer=SecurityLayer.STANDARD,
              output_raw=False, input_raw=False):
        if input_raw:
            package = encoded if isinstance(encoded, bytes) else encoded.encode('utf-8')
        else:
            if not encoded:
                raise ValueError("  Encoded data cannot be empty.")
            package = encoded if isinstance(encoded, bytes) else base64.b64decode(encoded.encode('utf-8'))
        self._validate_key(key, 'dofbb')
        aad_pkg, salt, iv, ciphertext, mac_val = self._unpack(package, 'ofbb')
        if aad is not None and aad != aad_pkg:
            raise ValueError("  AAD mismatch")
        enc_key, mac_key = self._derive_keys(key, salt, layer)
        to_verify = package[:-len(mac_val)] if mac_val else package
        if mac_val and not hmac.compare_digest(mac_val, self._mac(mac_key, to_verify)):
            raise ValueError("  MAC verification failed")
        cipher = AES.new(enc_key, AES.MODE_OFB, iv=iv)
        plain = cipher.decrypt(ciphertext)
        logger.debug("dofbb: decrypted %d bytes", len(plain))
        return plain if output_raw else self._to_str(plain)