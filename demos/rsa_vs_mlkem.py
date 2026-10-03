"""Quantum-threat demo: RSA (broken by Shor's algorithm) versus ML-KEM-768 (post-quantum).

Run:  python demos/rsa_vs_mlkem.py
"""

import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from securevault.core import pqc


def timed(fn, repeat: int = 5):
    start = time.perf_counter()
    for _ in range(repeat):
        result = fn()
    return result, (time.perf_counter() - start) / repeat * 1000


if __name__ == "__main__":
    secret = b"k" * 32
    oaep = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)

    rsa_key, rsa_gen = timed(lambda: rsa.generate_private_key(65537, 2048), 3)
    rsa_ct, rsa_enc = timed(lambda: rsa_key.public_key().encrypt(secret, oaep))
    _, rsa_dec = timed(lambda: rsa_key.decrypt(rsa_ct, oaep))

    (pk, sk), kem_gen = timed(pqc.generate_keypair)
    (kem_ct, _), kem_enc = timed(lambda: pqc.encapsulate(pk))
    _, kem_dec = timed(lambda: pqc.decapsulate(sk, kem_ct))

    print(f"{'':22}{'RSA-2048':>12}{'ML-KEM-768':>14}")
    print(f"{'key generation (ms)':22}{rsa_gen:>12.1f}{kem_gen:>14.1f}")
    print(f"{'encrypt / encaps (ms)':22}{rsa_enc:>12.2f}{kem_enc:>14.1f}")
    print(f"{'decrypt / decaps (ms)':22}{rsa_dec:>12.2f}{kem_dec:>14.1f}")
    print(f"{'public key (bytes)':22}{len(rsa_key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.PKCS1)):>12}{len(pk):>14}")
    print(f"{'ciphertext (bytes)':22}{len(rsa_ct):>12}{len(kem_ct):>14}")
    print("\nNote: kyber-py is pure Python, so its timings are much slower than a C library such")
    print("as liboqs would give. Compare SIZES, which do not depend on the implementation.")
    print("\nWhy it matters:")
    print("  * Shor's algorithm on a large quantum computer breaks RSA and elliptic curves.")
    print("  * An attacker can record encrypted traffic or files TODAY and decrypt them later")
    print("    ('harvest now, decrypt later'), so long-lived secrets need PQC now.")
    print("  * Grover's algorithm only halves symmetric strength, so AES-256 (about 128-bit")
    print("    post-quantum) stays safe. That is why the vault pairs ML-KEM with AES-256-GCM.")
