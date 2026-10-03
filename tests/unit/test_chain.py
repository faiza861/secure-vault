import copy

from securevault.audit import chain


def build(n=5):
    entries, prev = [], None
    for i in range(n):
        prev = chain.make_entry(prev, "upload", "tester", {"file_id": f"f{i}", "bytes": i}, 1000.0 + i)
        entries.append(prev)
    return entries


def test_empty_chain_is_valid():
    v = chain.verify([])
    assert v.ok and v.length == 0 and v.head_hash == chain.GENESIS_HASH


def test_valid_chain():
    entries = build()
    v = chain.verify(entries)
    assert v.ok and v.length == 5 and v.head_hash == entries[-1]["hash"]


def test_first_entry_links_to_genesis():
    assert build(1)[0]["prev_hash"] == chain.GENESIS_HASH


def test_modified_entry_detected():
    entries = build()
    entries[2]["details"]["bytes"] = 999
    v = chain.verify(entries)
    assert not v.ok and v.first_bad_index == 2 and "modified" in v.reason


def test_modified_and_rehashed_entry_breaks_next_link():
    entries = build()
    entries[2]["details"]["bytes"] = 999
    entries[2]["hash"] = chain.compute_hash(entries[2])  # attacker recomputes own hash
    v = chain.verify(entries)
    assert not v.ok and v.first_bad_index == 3 and "link" in v.reason


def test_deleted_entry_detected():
    entries = build()
    del entries[1]
    v = chain.verify(entries)
    assert not v.ok and v.first_bad_index == 1


def test_reordered_entries_detected():
    entries = build()
    entries[1], entries[2] = entries[2], entries[1]
    assert not chain.verify(entries).ok


def test_truncation_caught_only_with_anchor():
    entries = build()
    anchor = entries[-1]["hash"]
    truncated = entries[:3]
    assert chain.verify(truncated).ok  # consistent on its own
    v = chain.verify(truncated, expected_head=anchor)
    assert not v.ok and "anchor" in v.reason


def test_full_rewrite_caught_with_anchor():
    entries = build()
    anchor = entries[-1]["hash"]
    rewritten, prev = [], None
    for e in copy.deepcopy(entries):
        e["details"]["bytes"] = 0
        prev = chain.make_entry(prev, e["event"], e["actor"], e["details"], e["ts"])
        rewritten.append(prev)
    assert chain.verify(rewritten).ok
    assert not chain.verify(rewritten, expected_head=anchor).ok


def test_malformed_entry_does_not_crash():
    v = chain.verify([{"index": 0}])
    assert not v.ok and v.reason == "malformed entry"
