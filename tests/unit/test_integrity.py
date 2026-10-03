from securevault.core import integrity


def test_sha256_known_vector():
    assert (
        integrity.sha256_hex(b"abc")
        == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )


def test_hmac_known_vector_rfc4231_case2():
    tag = integrity.hmac_sha256(b"Jefe", b"what do ya want for nothing?")
    assert tag.hex() == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"


def test_hmac_verify():
    tag = integrity.hmac_sha256(b"k" * 32, b"data")
    assert integrity.verify_hmac(b"k" * 32, b"data", tag)
    assert not integrity.verify_hmac(b"k" * 32, b"datb", tag)
    assert not integrity.verify_hmac(b"j" * 32, b"data", tag)


def test_constant_time_equal():
    assert integrity.constant_time_equal("abc", "abc")
    assert not integrity.constant_time_equal("abc", "abd")
