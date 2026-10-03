import pytest
from cryptography.exceptions import InvalidTag

from securevault.core import cipher, pqc


def test_kem_roundtrip_and_sizes():
    pk, sk = pqc.generate_keypair()
    ct, secret = pqc.encapsulate(pk)
    assert len(pk) == 1184 and len(sk) == 2400
    assert len(ct) == pqc.KEM_CIPHERTEXT_SIZE and len(secret) == 32
    assert pqc.decapsulate(sk, ct) == secret


def test_each_encapsulation_is_different():
    pk, _ = pqc.generate_keypair()
    (ct1, s1), (ct2, s2) = pqc.encapsulate(pk), pqc.encapsulate(pk)
    assert ct1 != ct2 and s1 != s2


def test_wrap_unwrap_roundtrip():
    pk, sk = pqc.generate_keypair()
    dek = cipher.generate_key()
    wrapped = pqc.wrap_key(pk, dek, aad=b"file-1")
    assert pqc.unwrap_key(sk, wrapped, aad=b"file-1") == dek


def test_unwrap_with_wrong_secret_key_fails():
    pk, _ = pqc.generate_keypair()
    _, other_sk = pqc.generate_keypair()
    wrapped = pqc.wrap_key(pk, cipher.generate_key(), aad=b"f")
    with pytest.raises(InvalidTag):
        pqc.unwrap_key(other_sk, wrapped, aad=b"f")


def test_unwrap_with_wrong_context_fails():
    pk, sk = pqc.generate_keypair()
    wrapped = pqc.wrap_key(pk, cipher.generate_key(), aad=b"file-1")
    with pytest.raises(InvalidTag):
        pqc.unwrap_key(sk, wrapped, aad=b"file-2")


def test_tampered_wrapped_key_fails():
    pk, sk = pqc.generate_keypair()
    wrapped = bytearray(pqc.wrap_key(pk, cipher.generate_key(), aad=b"f"))
    wrapped[10] ^= 1  # flip a bit inside the KEM ciphertext -> implicit rejection
    with pytest.raises(InvalidTag):
        pqc.unwrap_key(sk, bytes(wrapped), aad=b"f")


def test_short_input_rejected():
    _, sk = pqc.generate_keypair()
    with pytest.raises(ValueError):
        pqc.unwrap_key(sk, b"short", aad=b"f")
