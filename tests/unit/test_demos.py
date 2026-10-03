from demos import legacy_ciphers as lc


def test_caesar_roundtrip_and_attack():
    cipher = lc.caesar(lc.PLAINTEXT, 11)
    assert lc.caesar(cipher, -11) == lc.PLAINTEXT
    shift, text = lc.break_caesar(cipher)
    assert shift == 11 and text == lc.PLAINTEXT


def test_vigenere_roundtrip_and_key_length_attack():
    cipher = lc.vigenere(lc.PLAINTEXT, "VAULT")
    assert lc.vigenere(cipher, "VAULT", decrypt=True) == lc.PLAINTEXT
    assert lc.guess_vigenere_key_length(cipher) == 5
