"""Passphrase -> key derivation with Argon2id (RFC 9106)."""

import os
from dataclasses import asdict, dataclass

from argon2.low_level import Type, hash_secret_raw

SALT_SIZE = 16
KEY_SIZE = 32


@dataclass(frozen=True)
class KdfParams:
    """Argon2id cost parameters. Defaults follow RFC 9106's second recommended option."""

    time_cost: int = 3
    memory_cost_kib: int = 64 * 1024
    parallelism: int = 4

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "KdfParams":
        return cls(
            time_cost=int(data["time_cost"]),
            memory_cost_kib=int(data["memory_cost_kib"]),
            parallelism=int(data["parallelism"]),
        )


# Cheap parameters, for unit tests only. Never use these for a real vault.
FAST_TEST_PARAMS = KdfParams(time_cost=1, memory_cost_kib=64, parallelism=1)


def generate_salt() -> bytes:
    return os.urandom(SALT_SIZE)


def derive_key(passphrase: str, salt: bytes, params: KdfParams = KdfParams()) -> bytes:
    """Derive a 256-bit key. The same passphrase, salt and params always give the same key."""
    if len(salt) < 8:
        raise ValueError("salt must be at least 8 bytes")
    return hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=salt,
        time_cost=params.time_cost,
        memory_cost=params.memory_cost_kib,
        parallelism=params.parallelism,
        hash_len=KEY_SIZE,
        type=Type.ID,
    )
