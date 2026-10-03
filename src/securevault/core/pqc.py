"""Post-quantum key encapsulation with ML-KEM-768 (NIST FIPS 203, formerly Kyber).

A KEM does not encrypt data directly. `encapsulate(public_key)` returns a random
shared secret plus a ciphertext; only the secret-key holder can turn that ciphertext
back into the same shared secret. We feed the secret through HKDF-SHA256 and use the
result as an AES-256-GCM key to wrap a data key. This is the standard "KEM-DEM" pattern.

Implementation: the pure-Python `kyber-py` package. It is correct and fine for learning
and demos, but it is not hardened against side channels. For production use liboqs.
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from kyber_py.ml_kem import ML_KEM_768

from securevault.core import cipher

ALGORITHM = "ML-KEM-768"
KEM_CIPHERTEXT_SIZE = 1088
_WRAP_INFO = b"securevault/v1/dek-wrap"


def generate_keypair() -> tuple[bytes, bytes]:
    """Return (public_key, secret_key)."""
    public_key, secret_key = ML_KEM_768.keygen()
    return public_key, secret_key


def encapsulate(public_key: bytes) -> tuple[bytes, bytes]:
    """Return (kem_ciphertext, shared_secret)."""
    shared_secret, kem_ciphertext = ML_KEM_768.encaps(public_key)
    return kem_ciphertext, shared_secret


def decapsulate(secret_key: bytes, kem_ciphertext: bytes) -> bytes:
    """Recover the shared secret. ML-KEM never errors on a bad ciphertext: it returns a
    pseudo-random secret instead (implicit rejection), so tampering shows up later as an
    AES-GCM authentication failure."""
    return ML_KEM_768.decaps(secret_key, kem_ciphertext)


def _wrap_key_from_secret(shared_secret: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_WRAP_INFO).derive(
        shared_secret
    )


def wrap_key(public_key: bytes, key: bytes, aad: bytes) -> bytes:
    """Wrap `key` (e.g. a file's data key) so only the secret-key holder can unwrap it.

    Output: kem_ciphertext (1088 bytes) || AES-GCM(wrap_key, key, aad).
    `aad` binds the wrapped key to its context (we use the file id).
    """
    kem_ct, shared = encapsulate(public_key)
    return kem_ct + cipher.encrypt(_wrap_key_from_secret(shared), key, aad)


def unwrap_key(secret_key: bytes, wrapped: bytes, aad: bytes) -> bytes:
    """Inverse of wrap_key. Raises cryptography.exceptions.InvalidTag if wrong or tampered."""
    if len(wrapped) <= KEM_CIPHERTEXT_SIZE:
        raise ValueError("wrapped key is too short")
    kem_ct, sealed = wrapped[:KEM_CIPHERTEXT_SIZE], wrapped[KEM_CIPHERTEXT_SIZE:]
    shared = decapsulate(secret_key, kem_ct)
    return cipher.decrypt(_wrap_key_from_secret(shared), sealed, aad)
