"""Lab 05: why the cipher MODE matters. ECB leaks patterns; GCM does not.

Run:  python demos/ecb_vs_gcm.py
(ECB is used here only to show the flaw. The vault never uses it.)
"""

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from securevault.core import cipher


def blocks(data: bytes) -> list[bytes]:
    return [data[i : i + 16] for i in range(0, len(data), 16)]


def ecb_encrypt(key: bytes, data: bytes) -> bytes:
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(data) + enc.finalize()


if __name__ == "__main__":
    key = os.urandom(32)
    # Pretend image: a flat block of "white" pixels with a dark pattern in the middle.
    message = b"WHITEWHITEWHITE!" * 6 + b"SECRET-PATTERN-1" * 4 + b"WHITEWHITEWHITE!" * 6

    ecb = blocks(ecb_encrypt(key, message))
    gcm = blocks(cipher.encrypt(key, message)[cipher.NONCE_SIZE :])

    print(f"Plaintext blocks : {len(blocks(message))}, distinct: {len(set(blocks(message)))}")
    print(f"ECB ciphertext   : distinct blocks = {len(set(ecb))}  <- repeats are visible!")
    print(f"GCM ciphertext   : distinct blocks = {len(set(gcm))}  <- looks random")
    print("\nECB encrypts equal plaintext blocks to equal ciphertext blocks, so structure leaks")
    print("(the famous 'ECB penguin'). GCM mixes a counter and a fresh nonce into every block,")
    print("and also authenticates the data, which ECB does not do at all.")
    tampered = bytearray(cipher.encrypt(key, message))
    tampered[20] ^= 1
    try:
        cipher.decrypt(key, bytes(tampered))
    except InvalidTag as exc:
        print(f"\nFlip one bit in GCM output -> decryption refused ({type(exc).__name__}).")
