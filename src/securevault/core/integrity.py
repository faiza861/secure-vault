"""SHA-256 fingerprints and HMAC-SHA256 tags."""

import hashlib
import hmac


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def verify_hmac(key: bytes, data: bytes, tag: bytes) -> bool:
    """Constant-time comparison, so timing does not leak how many bytes matched."""
    return hmac.compare_digest(hmac_sha256(key, data), tag)


def constant_time_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())
