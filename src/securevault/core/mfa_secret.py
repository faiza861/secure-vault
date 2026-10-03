"""Protects the TOTP secret inside the keystore. Reuses `cipher` and `envelope.b64e/b64d` unchanged.

    keystore["mfa"] = {"enabled": true, "enc_secret": <b64 AES-256-GCM blob>, "version": 1}

SECURITY DESIGN
* The secret is encrypted with AES-256-GCM under a SUBKEY of the KEK: HKDF-SHA256 with its own
  `info` label. The KEK itself is therefore never used directly for two different purposes
  (it already encrypts the ML-KEM secret keys), and the two uses cannot be confused.
* The associated data names the purpose, so this ciphertext cannot be swapped into another
  slot of the keystore (or the other way round) without failing authentication.
* A keystore with no "mfa" block is a legacy / MFA-disabled vault and is handled by callers.
* The secret exists in plaintext only in memory, while needed for one verification.
"""

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from securevault.core import cipher
from securevault.core.envelope import b64d, b64e
from securevault.utils.exceptions import IntegrityError

MFA_BLOCK_VERSION = 1
_HKDF_INFO = b"securevault/mfa/v1"  # distinct label: a different key from the KEK or any wrap key
_AAD = b"securevault/mfa/v1/totp-secret"


def _subkey(kek: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_HKDF_INFO).derive(kek)


def seal(kek: bytes, secret: str) -> dict:
    """Encrypt a Base32 TOTP secret and return the keystore block."""
    blob = cipher.encrypt(_subkey(kek), secret.encode("ascii"), _AAD)
    return {"enabled": True, "enc_secret": b64e(blob), "version": MFA_BLOCK_VERSION}


def open_secret(kek: bytes, block: dict) -> str:
    """Decrypt the secret. ANY problem (tampering, wrong key, malformed block) is an IntegrityError,
    never a crash and never a silent pass."""
    try:
        if block.get("version") != MFA_BLOCK_VERSION:
            raise IntegrityError("unsupported MFA block version")
        return cipher.decrypt(_subkey(kek), b64d(block["enc_secret"]), _AAD).decode("ascii")
    except IntegrityError:
        raise
    except (InvalidTag, ValueError, KeyError, TypeError, AttributeError):
        raise IntegrityError("MFA data failed authentication") from None


def rewrap(old_kek: bytes, new_kek: bytes, block: dict) -> dict:
    """Move the secret from the old KEK to the new one (used when the passphrase changes)."""
    return seal(new_kek, open_secret(old_kek, block))
