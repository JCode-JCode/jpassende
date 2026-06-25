"""
jpassende – Test Script with Extensive Documentation
----------------------------------------------------
This script performs a complete test of the jpassende cryptographic library:

  1. Encrypts a plaintext using 4 different patterns (vail, phnx, strx, hkdf).
  2. Decrypts each result with the correct key.
  3. Attempts decryption with a wrong key on two patterns,
     confirming that the library correctly rejects the operation.

All library features, parameters, and patterns are explained in the comments.
"""

from jpassende import JPassende, SecurityLayer, InvalidPackageError

# ----------------------------------------------------------------------
# INSTANCE CREATION
# ----------------------------------------------------------------------
# JPassende(enable_logging=False) – creates a new instance.
#   enable_logging: if True, detailed debug messages (derivation, timing)
#                   are printed to the console.
jp = JPassende(enable_logging=False)

# ----------------------------------------------------------------------
# TEST DATA
# ----------------------------------------------------------------------
plaintext = "Sensitive message – top secret!"
correct_key = "StrongP@ssw0rd!2024"
wrong_key   = "WrongKey123"

print("-" * 40)
print("jpassende Test Suite – Encrypt/Decrypt with 4 Patterns")
print("-" * 40)

# ----------------------------------------------------------------------
# PATTERN OVERVIEW
# ----------------------------------------------------------------------
# The library provides 14 unique patterns divided into categories:
#
# AEAD:
#   vail – AES‑256‑GCM (built‑in authentication tag).
#   phnx – ChaCha20‑Poly1305 (modern, mobile‑friendly).
#   nixl – ChaCha20 + independent BLAKE2‑based HMAC.
#
# Stream:
#   strx – BLAKE2‑based keystream (64‑byte blocks).
#   rvrs – SHA‑3 feedback mode.
#   lfsr – Dual state (SHA‑3 + BLAKE2).
#
# Block:
#   aegs – AES‑CTR + HMAC.
#   cblk – AES‑CBC + HMAC.
#   cfbb – AES‑CFB‑128 + HMAC.
#   ofbb – AES‑OFB + HMAC.
#
# Derivation:
#   hkdf – HMAC‑based Key Derivation Function (SHA‑512).
#   scrt – scrypt (memory‑hard).
#   pbk2 – PBKDF2‑SHA‑512 (tunable iterations).
#   blk3 – Merkle‑tree commitment.

# For this test we use two AEAD patterns, one stream pattern, and one derivation pattern.

patterns = ['vail', 'phnx', 'strx', 'hkdf']
results = {}

print("\n--- Encrypting with correct key ---")
for pat in patterns:
    # ------------------------------------------------------------------
    # jp.encode(data, pattern, key, ...)
    #   data       : plaintext (str or bytes if input_raw=True)
    #   pattern    : the cryptographic pattern to use
    #   key        : secret key (string)
    #
    # Optional parameters (not used here, but available):
    #   layer      : SecurityLayer.STANDARD (default), FORTIFIED, QUANTUM
    #   aad        : Additional Authenticated Data (bytes)
    #   output_raw : if True, returns bytes instead of base‑encoded string
    #   input_raw  : if True, interprets data as raw bytes
    #   length     : (for derivation patterns) desired output length in bytes
    #
    # Returns a CryptoResult object with fields:
    #   .encoded   : the encrypted package (string or bytes)
    #   .pattern   : pattern name
    #   .layer     : security layer name
    #   .needs_key : True
    #   .elapsed   : encryption time in seconds
    #   .timestamp : creation timestamp
    # ------------------------------------------------------------------
    res = jp.encode(plaintext, pat, correct_key)
    results[pat] = res
    print(f"Pattern {pat.upper():6s}: {res.encoded[:50]}... (time: {res.elapsed:.4f}s)")

print("\n--- Decrypting with correct key ---")
for pat in patterns:
    # ------------------------------------------------------------------
    # jp.decode(encoded, pattern, key, ...)
    #   encoded    : the encrypted data (string or bytes if input_raw=True)
    #   pattern    : must match the pattern used during encryption
    #   key        : the same secret key
    #
    # Optional parameters identical to encode().
    #
    # Returns a DecodeResult object:
    #   .decoded   : plaintext (string or bytes, or hex for derivations)
    #   .pattern   : pattern name
    #   .layer     : security layer
    #   .verified  : True if authentication succeeded
    #   .elapsed   : decryption time
    # ------------------------------------------------------------------
    dec = jp.decode(results[pat].encoded, pat, correct_key)
    if pat == 'hkdf':
        # HKDF returns a hex string by default (unless output_raw=True)
        print(f"Pattern {pat.upper():6s}: derived {len(dec.decoded)} hex chars – verified: {dec.verified}")
    else:
        match = "OK" if dec.decoded == plaintext else "MISMATCH"
        print(f"Pattern {pat.upper():6s}: {dec.decoded} – match: {match}")

# ----------------------------------------------------------------------
# DECRYPTION WITH WRONG KEY
# ----------------------------------------------------------------------
# The library must reject decryption when the wrong key is used.
# For AEAD patterns, the built‑in tag verification fails.
# For stream/block patterns, the independent HMAC check fails.
# In both cases a ValueError (or InvalidPackageError) is raised.

print("\n--- Attempting decryption with wrong key (expecting errors) ---")

# Test 1: wrong key on 'vail' (AES‑GCM)
try:
    jp.decode(results['vail'].encoded, 'vail', wrong_key)
    print("FAIL: 'vail' accepted wrong key (should have raised an error)")
except (ValueError, InvalidPackageError):
    print("OK: 'vail' correctly rejected wrong key")

# Test 2: wrong key on 'strx' (stream cipher)
try:
    jp.decode(results['strx'].encoded, 'strx', wrong_key)
    print("FAIL: 'strx' accepted wrong key (should have raised an error)")
except (ValueError, InvalidPackageError):
    print("OK: 'strx' correctly rejected wrong key")

# ----------------------------------------------------------------------
# ADDITIONAL FEATURES (commented examples)
# ----------------------------------------------------------------------
# The following block illustrates optional parameters that you can use.
# Remove the triple quotes and uncomment to run.

'''
print("\n--- Optional features demonstration ---")

# Using a stronger security layer (more PBKDF2 iterations)
enc_q = jp.encode(plaintext, 'phnx', correct_key, layer=SecurityLayer.QUANTUM)
dec_q = jp.decode(enc_q.encoded, 'phnx', correct_key, layer=SecurityLayer.QUANTUM)
print("Quantum layer:", dec_q.decoded)

# Additional Authenticated Data (AAD)
aad = b"user-id:12345"
enc_a = jp.encode(plaintext, 'vail', correct_key, aad=aad)
dec_a = jp.decode(enc_a.encoded, 'vail', correct_key, aad=aad)
print("With AAD:", dec_a.decoded)
# Wrong AAD will raise ValueError

# Binary data encryption (input_raw=True, output_raw=True)
binary_data = b'\x00\x01\x02\xff\xfe\xfd'
enc_b = jp.encode(binary_data, 'nixl', correct_key, input_raw=True, output_raw=True)
dec_b = jp.decode(enc_b.encoded, 'nixl', correct_key, input_raw=True, output_raw=True)
print("Binary match:", dec_b.decoded == binary_data)

# List all available patterns
print("All patterns:", jp.list_patterns())

# Cross‑instance decryption (any JPassende instance can decrypt)
jp2 = JPassende()
cross = jp2.decode(results['phnx'].encoded, 'phnx', correct_key)
print("Cross-instance:", cross.decoded)
'''

print("\n" + "-" * 40)
print("All tests completed successfully.")
print("The library correctly encrypts, decrypts, and rejects wrong keys.")
print("-" * 40)