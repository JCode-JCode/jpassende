# Changelog

All notable changes to **jpassende** are documented in this file.

---

## [1.1.0] - 2026-09-14

**· Fixed** – `lfsr`/`dlfsr` used to hash a full 32‑byte digest per pattern and then discard 31 of those bytes, hashing once per **byte** of input. Both functions now consume the entire digest as a 32‑byte keystream block, cutting the number of hash calls by ~32x for the same input.

**· Fixed** – `_unpack_derivation` performed index access (`package[4]`, `package[5]`, `package[6]`) before validating the input length, so a short or malformed package could raise a raw `IndexError` instead of a clean `InvalidPackageError`. Length checks now mirror `_unpack`.

**· Fixed** – Version mismatch between `jpassende/_version.py` (`1.0.0`) and `pyproject.toml` (`1.1.0`). Both now report `1.1.0`.

**· Changed** – `_pack` and `_pack_derivation` no longer build intermediate `header`/`body`/`aad_block` variables; the header, AAD block, and body are appended directly to `payload`. Output format and byte layout are unchanged.

**· Changed** – `lfsr`/`dlfsr` write new keystream state directly into `stateA`/`stateB` instead of through temporary `ks_a`/`ks_b` variables. Encryption/decryption behavior is unchanged.

**· Added** – README section documenting the official JavaScript port, **jjspassende**.

**· Added** – Python 3.13 classifier in `pyproject.toml`.

---

## [1.0.0] - Initial Release

**· Added** – Initial release of jpassende with 14 patterns across four categories: AEAD (`vail`, `phnx`, `nixl`), Stream (`strx`, `rvrs`, `lfsr`), Block (`aegs`, `cblk`, `cfbb`, `ofbb`), and Derivation (`hkdf`, `scrt`, `pbk2`, `blk3`).

**· Added** – Three selectable security layers (`STANDARD`, `FORTIFIED`, `QUANTUM`) controlling PBKDF2 iteration counts.

**· Added** – Self‑describing binary package format (magic header, version byte, pattern ID, optional AAD).

**· Added** – Thread‑safe LRU cache for PBKDF2 key derivations.

**· Added** – `InvalidPackageError` for malformed or corrupted packages.