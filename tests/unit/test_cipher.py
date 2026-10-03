import pytest
from cryptography.exceptions import InvalidTag

from securevault.core import cipher


def test_roundtrip():
    key = cipher.generate_key()
    assert cipher.decrypt(key, cipher.encrypt(key, b"secret")) == b"secret"


def test_empty_plaintext_roundtrip():
    key = cipher.generate_key()
    assert cipher.decrypt(key, cipher.encrypt(key, b"")) == b""


def test_tamper_detected():
    key = cipher.generate_key()
    blob = bytearray(cipher.encrypt(key, b"secret"))
    blob[-1] ^= 1
    with pytest.raises(InvalidTag):
        cipher.decrypt(key, bytes(blob))


def test_wrong_key_fails():
    blob = cipher.encrypt(cipher.generate_key(), b"secret")
    with pytest.raises(InvalidTag):
        cipher.decrypt(cipher.generate_key(), blob)


def test_nonce_is_fresh_every_time():
    key = cipher.generate_key()
    a, b = cipher.encrypt(key, b"same"), cipher.encrypt(key, b"same")
    assert a != b
    assert a[: cipher.NONCE_SIZE] != b[: cipher.NONCE_SIZE]


def test_aad_is_bound():
    key = cipher.generate_key()
    blob = cipher.encrypt(key, b"secret", aad=b"file-1")
    assert cipher.decrypt(key, blob, aad=b"file-1") == b"secret"
    with pytest.raises(InvalidTag):
        cipher.decrypt(key, blob, aad=b"file-2")


def test_rejects_bad_key_size_and_short_blob():
    with pytest.raises(ValueError):
        cipher.encrypt(b"short", b"x")
    with pytest.raises(ValueError):
        cipher.decrypt(cipher.generate_key(), b"tiny")
