"""Authenticated encryption with AES-256-GCM.

Blob layout: nonce (12 bytes) || ciphertext || tag (16 bytes).
A fresh random 96-bit nonce is used for every call, so never reuse one key for
more than a very large number of messages (the NIST limit is 2**32 random-nonce uses).
"""

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_SIZE = 12
KEY_SIZE = 32
TAG_SIZE = 16


def generate_key() -> bytes:
    return AESGCM.generate_key(bit_length=256)


def _check_key(key: bytes) -> None:
    if len(key) != KEY_SIZE:
        raise ValueError("key must be exactly 32 bytes (AES-256)")


def encrypt(key: bytes, plaintext: bytes, aad: bytes | None = None) -> bytes:
    """Encrypt and authenticate. `aad` is authenticated but not encrypted."""
    _check_key(key)
    nonce = os.urandom(NONCE_SIZE)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def decrypt(key: bytes, blob: bytes, aad: bytes | None = None) -> bytes:
    """Verify and decrypt. Raises cryptography.exceptions.InvalidTag on any change."""
    _check_key(key)
    if len(blob) < NONCE_SIZE + TAG_SIZE:
        raise ValueError("ciphertext is too short")
    nonce, ciphertext = blob[:NONCE_SIZE], blob[NONCE_SIZE:]
    return AESGCM(key).decrypt(nonce, ciphertext, aad)
