"""TOTP against the published RFC test vectors, plus window and input edge cases."""

import base64

import pytest

from securevault.core import totp

RFC_SECRET_BYTES = b"12345678901234567890"  # the ASCII key used by both RFCs
RFC_SECRET = base64.b32encode(RFC_SECRET_BYTES).decode()


def test_rfc4226_hotp_vectors():
    expected = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"]
    assert [totp.hotp(RFC_SECRET_BYTES, c) for c in range(10)] == expected


@pytest.mark.parametrize(
    ("when", "code8"),
    [(59, "94287082"), (1111111109, "07081804"), (1111111111, "14050471"),
     (1234567890, "89005924"), (2000000000, "69279037"), (20000000000, "65353130")],
)
def test_rfc6238_sha1_vectors(when, code8):
    assert totp.hotp(RFC_SECRET_BYTES, when // 30, digits=8) == code8
    assert totp.totp(RFC_SECRET, now=when) == code8[-6:]  # our 6-digit codes are the last 6 digits


def test_verify_returns_matched_step():
    now = 1_700_000_000.0
    assert totp.verify(RFC_SECRET, totp.totp(RFC_SECRET, now), now) == int(now // 30)


def test_window_edges():
    now = 1_700_000_015.0
    step = int(now // 30)
    for offset, ok in [(-2, False), (-1, True), (0, True), (1, True), (2, False)]:
        code = totp.hotp(RFC_SECRET_BYTES, step + offset)
        assert (totp.verify(RFC_SECRET, code, now) == step + offset) if ok else (totp.verify(RFC_SECRET, code, now) is None)


@pytest.mark.parametrize("bad", ["", "12345", "1234567", "abcdef", "12 456", "١٢٣٤٥٦", "+12345", "12345\n", None, 123456])
def test_malformed_codes_are_rejected(bad):
    assert totp.verify(RFC_SECRET, bad, 1_700_000_000.0) is None


def test_secret_shape_and_randomness():
    a, b = totp.generate_secret(), totp.generate_secret()
    assert a != b and len(a) == 32 and totp.is_valid_secret(a)  # 160 bits -> 32 Base32 chars, no padding
    assert not totp.is_valid_secret("short") and not totp.is_valid_secret("!!!!") and not totp.is_valid_secret(None)


def test_provisioning_uri():
    uri = totp.provisioning_uri("ABCDEFGHIJKLMNOP", "me@example.com")
    assert uri.startswith("otpauth://totp/Secure%20Vault:me%40example.com?")
    for part in ("secret=ABCDEFGHIJKLMNOP", "issuer=Secure%20Vault", "digits=6", "period=30", "algorithm=SHA1"):
        assert part in uri
