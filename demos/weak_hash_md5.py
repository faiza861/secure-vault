"""Lab 06: weak and fast hashes. Why MD5 is wrong for integrity and passwords.

Run:  python demos/weak_hash_md5.py
"""

import hashlib
import time

from securevault.core import kdf
from securevault.core.kdf import KdfParams

WORDLIST = ["123456", "password", "letmein", "qwerty", "dragon", "iloveyou", "monkey", "secret", "admin", "welcome"]


def rate(fn, seconds: float = 0.3) -> float:
    count, end = 0, time.perf_counter() + seconds
    while time.perf_counter() < end:
        fn()
        count += 1
    return count / seconds


if __name__ == "__main__":
    stolen = hashlib.md5(b"letmein").hexdigest()
    print(f"Stolen unsalted MD5 hash: {stolen}")
    for guess in WORDLIST:
        if hashlib.md5(guess.encode()).hexdigest() == stolen:
            print(f"  cracked instantly from a tiny wordlist: '{guess}'")
    print()

    md5 = rate(lambda: hashlib.md5(b"password").digest())
    sha = rate(lambda: hashlib.sha256(b"password").digest())
    salt = kdf.generate_salt()
    argon = rate(lambda: kdf.derive_key("password", salt, KdfParams()), 1.0)
    print("Guesses per second on THIS computer, single core:")
    print(f"  MD5       {md5:>12,.0f}")
    print(f"  SHA-256   {sha:>12,.0f}")
    print(f"  Argon2id  {argon:>12,.1f}   <- deliberately slow and memory-hungry")
    print(f"\nArgon2id is about {md5 / argon:,.0f}x slower than MD5 per guess, which is exactly the point.")
    print("\nAlso: MD5 collisions (two different inputs, same hash) are practical to produce")
    print("since 2004, so it must never be used for integrity. The vault uses SHA-256 for")
    print("fingerprints, HMAC-SHA256 for keyed checks, and Argon2id for passphrases.")
