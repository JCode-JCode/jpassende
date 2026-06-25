[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![PyPI version](https://img.shields.io/pypi/v/jpassende)](https://pypi.org/project/jpassende/)
[![PyPI project](https://img.shields.io/badge/PyPI-jpassende-blue)](https://pypi.org/project/jpassende/)

<br>

<img src="docs/images/jpassende-logo.png" alt="jpassende">

<br>

**jpassende** is a high‑performance, multi‑pattern cryptographic library for Python that goes far beyond standard encryption. It offers 14 unique patterns spanning AEAD, stream ciphers, block ciphers, and key derivation – all wrapped in a simple, consistent API. Every pattern uses its own distinct combination of algorithms and constructions, making your ciphertext immediately recognisable and self‑describing.

---

## Quick Start – Encrypt & Decrypt in Two Lines

```python
from jpassende import JPassende

jp = JPassende()

result = jp.encode("Hello, World!", "vail", key="my_secret")
print(result.encoded)

original = jp.decode(result.encoded, "vail", key="my_secret")
print(original.decoded)
```

---

## Main Capabilities

**· AEAD Patterns** – vail (AES‑GCM), phnx (ChaCha20‑Poly1305), nixl (ChaCha20 + independent HMAC). All three provide authenticated encryption with associated data (AAD) support.

**· Stream Patterns** – strx (BLAKE2‑based keystream), rvrs (SHA‑3 feedback mode), lfsr (dual‑state SHA‑3 / BLAKE2 generator). Byte‑by‑byte encryption without padding, ideal for streaming data.

**· Block Patterns** – aegs (AES‑CTR + HMAC), cblk (AES‑CBC + HMAC), cfbb (AES‑CFB‑128 + HMAC), ofbb (AES‑OFB + HMAC). Standard block cipher modes, each individually authenticated.

**· Derivation Patterns** – hkdf (HMAC‑based Extract‑and‑Expand), scrt (scrypt), pbk2 (PBKDF2‑SHA‑512), blk3 (Merkle‑tree commitment). Password hashing, key material generation, and data integrity commitments.

**· Security Layers** – Every pattern supports three selectable security layers: STANDARD (300k PBKDF2 iterations), FORTIFIED (600k), and QUANTUM (1.2M). You control the trade‑off between speed and brute‑force resistance.

**· Binary & Text I/O** – output_raw returns bytes instead of base‑encoded strings. input_raw accepts raw bytes directly, so you can encrypt binary files, images, or any byte sequence.

**· Cross‑Instance Decryption** – Packages carry all the metadata (magic, version, pattern ID, salt, nonce) needed for decryption. Any JPassende instance anywhere can decrypt, provided it has the same key.

**· Self‑Describing Packages** – The binary format includes a magic header, version byte, pattern identifier, and optional AAD. No more guessing which algorithm was used.

**· LRU Key Cache** – PBKDF2 derivations are cached (thread‑safe LRU) to avoid redundant work when the same password is reused.

**· Invalid Package Detection** – A dedicated InvalidPackageError is raised when the package structure, magic, or version is invalid.

**· Zero Plaintext Password Storage** – Cache keys are derived from a BLAKE2b hash of (password + salt + parameters), never from the password itself.

---

## Pattern Status

The patterns nixl, strx, rvrs, lfsr, aegs, cblk, cfbb, ofbb, hkdf, scrt, pbk2, and blk3 are custom constructions created exclusively for jpassende. They are currently experimental and under active development – their internal design may evolve as we gather feedback and perform further security analysis. The patterns vail (AES‑256‑GCM) and phnx (ChaCha20‑Poly1305) use standardized, well‑vetted algorithms and are considered stable. If you plan to use the experimental patterns in production, we strongly recommend performing your own security review and staying updated with new releases.

---

## Installation

```bash
pip install jpassende
```

jpassende depends only on pycryptodome (≥ 3.18) and Python's standard library.

---

## More Examples

Encrypting Binary Data (input_raw / output_raw)

```python
from jpassende import JPassende

jp = JPassende()
image = open("photo.png", "rb").read()

enc_pkg = jp.encode(image, "nixl", key="secret", input_raw=True, output_raw=True)

dec_bytes = jp.decode(enc_pkg.encoded, "nixl", key="secret",
                      input_raw=True, output_raw=True).decoded

with open("photo_decrypted.png", "wb") as f:
    f.write(dec_bytes)
```

## Choosing a Security Layer

```python
from jpassende import JPassende, SecurityLayer

jp = JPassende()

result = jp.encode("Sensitive data", "phnx", key="strong",
                   layer=SecurityLayer.QUANTUM)
print(result.layer)
```

## Using AAD (Additional Authenticated Data)

```python
aad = b"user-id:12345"
result = jp.encode("Hello", "vail", key="secret", aad=aad)
decoded = jp.decode(result.encoded, "vail", key="secret", aad=aad)
```

## Key Derivation – HKDF

```python
derived = jp.encode("master-seed", "hkdf", key="secret", length=32)
print(derived.encoded[:30] + "...")

verified = jp.decode(derived.encoded, "hkdf", key="secret")
print(verified.decoded[:20] + "...")
```

## List All Available Patterns

```python
from jpassende import JPassende

print(JPassende.PATTERNS.keys())
```

---

## Error Handling

```python
from jpassende import JPassende, InvalidPackageError

jp = JPassende()

try:
    jp.decode("not-valid-data", "vail", key="secret")
except InvalidPackageError as e:
    print(f"Package error: {e}")
except ValueError as e:
    print(f"Other error: {e}")
```

---

## Issues and Contributions

Bug reports and feature requests are welcome via GitHub Issues. Pull requests should maintain the existing code style and include tests where appropriate.

---

## Links

**· GitHub repository:**
https://github.com/JCode-JCode/jpassende

**· PyPI page:**
https://pypi.org/project/jpassende/

---

## License

This project is licensed under the Apache License 2.0 – see the LICENSE file for details.

---

Designed and built with love by **J Code**
