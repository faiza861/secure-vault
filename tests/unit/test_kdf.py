import pytest

from securevault.core import kdf
from securevault.core.kdf import FAST_TEST_PARAMS, KdfParams


def test_deterministic():
    salt = kdf.generate_salt()
    a = kdf.derive_key("passphrase-123", salt, FAST_TEST_PARAMS)
    b = kdf.derive_key("passphrase-123", salt, FAST_TEST_PARAMS)
    assert a == b and len(a) == 32


def test_different_salt_or_passphrase_changes_key():
    salt = kdf.generate_salt()
    base = kdf.derive_key("passphrase-123", salt, FAST_TEST_PARAMS)
    assert kdf.derive_key("passphrase-124", salt, FAST_TEST_PARAMS) != base
    assert kdf.derive_key("passphrase-123", kdf.generate_salt(), FAST_TEST_PARAMS) != base


def test_params_change_key():
    salt = kdf.generate_salt()
    a = kdf.derive_key("pw-pw-pw-pw", salt, FAST_TEST_PARAMS)
    b = kdf.derive_key("pw-pw-pw-pw", salt, KdfParams(time_cost=2, memory_cost_kib=64, parallelism=1))
    assert a != b


def test_params_roundtrip_dict():
    p = KdfParams(time_cost=2, memory_cost_kib=1024, parallelism=2)
    assert KdfParams.from_dict(p.to_dict()) == p


def test_short_salt_rejected():
    with pytest.raises(ValueError):
        kdf.derive_key("pw", b"abc", FAST_TEST_PARAMS)


def test_default_params_match_rfc9106_recommendation():
    p = KdfParams()
    assert (p.time_cost, p.memory_cost_kib, p.parallelism) == (3, 65536, 4)
