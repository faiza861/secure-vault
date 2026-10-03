"""Envelope encryption: the key hierarchy. Pure functions, no I/O.

    passphrase --Argon2id--> KEK  (key-encryption key, symmetric, never stored)
        KEK --AES-256-GCM--> ML-KEM-768 secret key   (stored encrypted in the keystore)
        ML-KEM-768 public key --KEM + HKDF + AES-GCM--> DEK   (per-file data key)
            DEK --AES-256-GCM--> file contents and file name

Why a hierarchy:
  * Uploading needs only the public key, so a locked vault can still accept files.
  * Changing the passphrase re-encrypts one small secret key, not every file.
  * Rotating the ML-KEM key pair re-wraps each file's 32-byte DEK, not the file data.
  * Every ciphertext is bound to its file id through AES-GCM associated data (AAD), so
    blobs and wrapped keys cannot be swapped between files without detection.
"""

import base64
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidTag

from securevault.core import cipher, kdf, pqc
from securevault.core.kdf import KdfParams
from securevault.utils.exceptions import IntegrityError, InvalidPassphrase

KEYSTORE_FORMAT = 1


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"), validate=True)


def _sk_aad(version: int) -> bytes:
    return b"securevault/v1/kem-secret-key/" + str(version).encode()


def _data_aad(file_id: str) -> bytes:
    return b"securevault/v1/data/" + file_id.encode()


def _name_aad(file_id: str) -> bytes:
    return b"securevault/v1/name/" + file_id.encode()


def _dek_aad(file_id: str) -> bytes:
    return b"securevault/v1/dek/" + file_id.encode()


@dataclass
class UnlockedKeys:
    """Key material held in memory only while the vault is unlocked."""

    kek: bytes
    secret_keys: dict[int, bytes] = field(default_factory=dict)  # key_version -> ML-KEM sk


# ---------------------------------------------------------------- keystore


def _new_kem_entry(version: int, kek: bytes) -> tuple[dict, bytes]:
    public_key, secret_key = pqc.generate_keypair()
    entry = {
        "version": version,
        "public_key": b64e(public_key),
        "secret_key_enc": b64e(cipher.encrypt(kek, secret_key, _sk_aad(version))),
    }
    return entry, secret_key


def create_keystore(passphrase: str, params: KdfParams) -> tuple[dict, UnlockedKeys]:
    salt = kdf.generate_salt()
    kek = kdf.derive_key(passphrase, salt, params)
    entry, secret_key = _new_kem_entry(1, kek)
    keystore = {
        "format": KEYSTORE_FORMAT,
        "kdf": {"algorithm": "argon2id", "salt": b64e(salt), **params.to_dict()},
        "kem": {"algorithm": pqc.ALGORITHM},
        "active_version": 1,
        "keys": [entry],
    }
    return keystore, UnlockedKeys(kek=kek, secret_keys={1: secret_key})


def unlock(keystore: dict, passphrase: str) -> UnlockedKeys:
    """Derive the KEK and decrypt every stored secret key. Wrong passphrase -> InvalidPassphrase."""
    params = KdfParams.from_dict(keystore["kdf"])
    kek = kdf.derive_key(passphrase, b64d(keystore["kdf"]["salt"]), params)
    secret_keys: dict[int, bytes] = {}
    for entry in keystore["keys"]:
        try:
            secret_keys[entry["version"]] = cipher.decrypt(
                kek, b64d(entry["secret_key_enc"]), _sk_aad(entry["version"])
            )
        except InvalidTag:
            raise InvalidPassphrase("wrong passphrase") from None
    return UnlockedKeys(kek=kek, secret_keys=secret_keys)


def active_public_key(keystore: dict) -> tuple[int, bytes]:
    version = keystore["active_version"]
    for entry in keystore["keys"]:
        if entry["version"] == version:
            return version, b64d(entry["public_key"])
    raise IntegrityError("keystore has no active key")


def change_passphrase(
    keystore: dict, unlocked: UnlockedKeys, new_passphrase: str, params: KdfParams
) -> tuple[dict, UnlockedKeys]:
    """Re-encrypt every secret key under a new KEK (new salt). No file data is touched."""
    salt = kdf.generate_salt()
    new_kek = kdf.derive_key(new_passphrase, salt, params)
    new_keystore = {
        **keystore,
        "kdf": {"algorithm": "argon2id", "salt": b64e(salt), **params.to_dict()},
        "keys": [
            {
                "version": e["version"],
                "public_key": e["public_key"],
                "secret_key_enc": b64e(
                    cipher.encrypt(new_kek, unlocked.secret_keys[e["version"]], _sk_aad(e["version"]))
                ),
            }
            for e in keystore["keys"]
        ],
    }
    return new_keystore, UnlockedKeys(kek=new_kek, secret_keys=dict(unlocked.secret_keys))


def add_key_version(keystore: dict, unlocked: UnlockedKeys) -> tuple[dict, UnlockedKeys]:
    """Generate a fresh ML-KEM key pair and make it active. Old keys stay until files migrate."""
    version = max(e["version"] for e in keystore["keys"]) + 1
    entry, secret_key = _new_kem_entry(version, unlocked.kek)
    new_keystore = {**keystore, "active_version": version, "keys": [*keystore["keys"], entry]}
    secret_keys = {**unlocked.secret_keys, version: secret_key}
    return new_keystore, UnlockedKeys(kek=unlocked.kek, secret_keys=secret_keys)


def drop_unused_versions(
    keystore: dict, unlocked: UnlockedKeys, in_use: set[int]
) -> tuple[dict, UnlockedKeys]:
    """Remove key versions that no file references any more (and never the active one)."""
    keep = set(in_use) | {keystore["active_version"]}
    new_keystore = {**keystore, "keys": [e for e in keystore["keys"] if e["version"] in keep]}
    secret_keys = {v: k for v, k in unlocked.secret_keys.items() if v in keep}
    return new_keystore, UnlockedKeys(kek=unlocked.kek, secret_keys=secret_keys)


# ------------------------------------------------------------------- files


@dataclass(frozen=True)
class SealedFile:
    blob: bytes  # nonce || ciphertext || tag
    wrapped_dek: str  # base64: ML-KEM ciphertext || AES-GCM(wrap key, DEK)
    enc_name: str  # base64: AES-GCM(DEK, file name)


def seal_file(public_key: bytes, file_id: str, name: str, data: bytes) -> SealedFile:
    """Encrypt a file under a brand-new random DEK, then wrap the DEK to the public key."""
    dek = cipher.generate_key()
    return SealedFile(
        blob=cipher.encrypt(dek, data, _data_aad(file_id)),
        wrapped_dek=b64e(pqc.wrap_key(public_key, dek, _dek_aad(file_id))),
        enc_name=b64e(cipher.encrypt(dek, name.encode("utf-8"), _name_aad(file_id))),
    )


def _unwrap(secret_key: bytes, file_id: str, wrapped_dek: str) -> bytes:
    try:
        return pqc.unwrap_key(secret_key, b64d(wrapped_dek), _dek_aad(file_id))
    except (InvalidTag, ValueError):
        raise IntegrityError("file key failed authentication") from None


def open_file(
    secret_key: bytes, file_id: str, blob: bytes, wrapped_dek: str, enc_name: str
) -> tuple[str, bytes]:
    """Return (name, plaintext). Any tampering raises IntegrityError."""
    dek = _unwrap(secret_key, file_id, wrapped_dek)
    try:
        data = cipher.decrypt(dek, blob, _data_aad(file_id))
        name = cipher.decrypt(dek, b64d(enc_name), _name_aad(file_id)).decode("utf-8")
    except (InvalidTag, ValueError):
        raise IntegrityError("file contents failed authentication") from None
    return name, data


def open_name(secret_key: bytes, file_id: str, wrapped_dek: str, enc_name: str) -> str:
    dek = _unwrap(secret_key, file_id, wrapped_dek)
    try:
        return cipher.decrypt(dek, b64d(enc_name), _name_aad(file_id)).decode("utf-8")
    except (InvalidTag, ValueError):
        raise IntegrityError("file name failed authentication") from None


def rewrap_dek(old_secret_key: bytes, new_public_key: bytes, file_id: str, wrapped_dek: str) -> str:
    """Move a DEK from one ML-KEM key pair to another. The file blob is not touched."""
    dek = _unwrap(old_secret_key, file_id, wrapped_dek)
    return b64e(pqc.wrap_key(new_public_key, dek, _dek_aad(file_id)))
