"""Lab 03: classical ciphers and why they are broken.

Run:  python demos/legacy_ciphers.py
"""

import string
from collections import Counter

ALPHA = string.ascii_uppercase


def caesar(text: str, shift: int) -> str:
    return "".join(ALPHA[(ALPHA.index(c) + shift) % 26] if c in ALPHA else c for c in text.upper())


def vigenere(text: str, key: str, decrypt: bool = False) -> str:
    out, i = [], 0
    for c in text.upper():
        if c in ALPHA:
            shift = ALPHA.index(key.upper()[i % len(key)]) * (-1 if decrypt else 1)
            out.append(ALPHA[(ALPHA.index(c) + shift) % 26])
            i += 1
        else:
            out.append(c)
    return "".join(out)


def break_caesar(cipher: str) -> tuple[int, str]:
    """Try all 26 keys and score each guess by how English-like its letter mix is."""
    common = "ETAOINSHRDLU"
    def score(t: str) -> int:
        return sum(common.count(c) for c in t if c in ALPHA)
    best = max(range(26), key=lambda s: score(caesar(cipher, -s)))
    return best, caesar(cipher, -best)


def guess_vigenere_key_length(cipher: str, max_len: int = 12) -> int:
    """Index-of-coincidence attack: the right key length makes each column look like English."""
    letters = [c for c in cipher.upper() if c in ALPHA]
    def ic(col: list[str]) -> float:
        n, counts = len(col), Counter(col)
        return sum(v * (v - 1) for v in counts.values()) / (n * (n - 1)) if n > 1 else 0
    def avg(k: int) -> float:
        return sum(ic(letters[i::k]) for i in range(k)) / k
    scores = {k: avg(k) for k in range(1, max_len + 1)}
    # the true length and its multiples all score high; pick the smallest near the best
    top = max(scores.values())
    return min(k for k, s in scores.items() if s >= top - 0.01)


PLAINTEXT = ("THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG WHILE THE SECURITY ENGINEER "
             "REVIEWS EVERY LINE OF CODE BEFORE ANYTHING IS DEPLOYED TO PRODUCTION AND "
             "THE ATTACKER WAITS FOR A MISTAKE THAT NEVER COMES")

if __name__ == "__main__":
    c = caesar(PLAINTEXT, 7)
    print("Caesar (shift 7):   ", c[:60], "...")
    shift, recovered = break_caesar(c)
    print(f"Attack: tried all 26 keys, best shift = {shift}\n  ->", recovered[:60], "...")
    print("  Only 26 possible keys, so brute force is instant.\n")

    key = "VAULT"
    v = vigenere(PLAINTEXT, key)
    print(f"Vigenere (key {key}):", v[:60], "...")
    length = guess_vigenere_key_length(v)
    print(f"Attack: index of coincidence suggests key length {length} (true length {len(key)})")
    print("  Once the length is known, each column is just a Caesar cipher.\n")
    print("Lesson: neither cipher belongs in the vault. AES-256-GCM replaces them.")
