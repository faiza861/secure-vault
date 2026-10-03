"""Tamper-evident audit log built as a hash chain.

Each entry stores the SHA-256 hash of the previous entry. Changing, deleting or
reordering any past entry changes its hash and breaks every link after it, so
`verify()` can point at the first bad entry.

Honest limitation: a plain hash chain only proves *consistency*. Someone with write
access to the whole log could rewrite every entry and recompute all hashes. To catch
that, record `head_hash` somewhere the attacker cannot reach (print it, email it,
commit it) and pass it to `verify(expected_head=...)` later. Truncation is caught the
same way.
"""

import json
from dataclasses import dataclass

from securevault.core.integrity import constant_time_equal, sha256_hex

GENESIS_HASH = "0" * 64


def compute_hash(entry: dict) -> str:
    """Hash of the entry's content (everything except its own `hash` field)."""
    body = {k: entry[k] for k in ("index", "ts", "event", "actor", "details", "prev_hash")}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return sha256_hex(canonical.encode("ascii"))


def make_entry(
    previous: dict | None, event: str, actor: str, details: dict | None, ts: float
) -> dict:
    """Build the next entry in the chain after `previous` (None for the first entry)."""
    entry = {
        "index": 0 if previous is None else previous["index"] + 1,
        "ts": round(float(ts), 3),
        "event": event,
        "actor": actor,
        "details": details or {},
        "prev_hash": GENESIS_HASH if previous is None else previous["hash"],
    }
    entry["hash"] = compute_hash(entry)
    return entry


@dataclass(frozen=True)
class Verification:
    ok: bool
    length: int
    head_hash: str
    first_bad_index: int | None = None
    reason: str = ""


def verify(entries: list[dict], expected_head: str | None = None) -> Verification:
    """Check every link. Returns the first problem found, if any."""
    prev_hash = GENESIS_HASH
    for position, entry in enumerate(entries):
        try:
            if entry["index"] != position:
                return Verification(False, len(entries), prev_hash, position, "index out of sequence")
            if entry["prev_hash"] != prev_hash:
                return Verification(False, len(entries), prev_hash, position, "broken link to previous entry")
            if not constant_time_equal(entry["hash"], compute_hash(entry)):
                return Verification(False, len(entries), prev_hash, position, "entry content was modified")
        except (KeyError, TypeError):
            return Verification(False, len(entries), prev_hash, position, "malformed entry")
        prev_hash = entry["hash"]
    if expected_head is not None and not constant_time_equal(prev_hash, expected_head):
        return Verification(
            False, len(entries), prev_hash, None, "head does not match the anchored hash (truncated or rewritten)"
        )
    return Verification(True, len(entries), prev_hash)
