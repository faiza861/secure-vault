import pytest

from securevault.core import envelope
from securevault.core.kdf import FAST_TEST_PARAMS
from securevault.utils.exceptions import IntegrityError, InvalidPassphrase

PW = "a long enough passphrase"
FID = "0" * 32


def make():
    keystore, unlocked = envelope.create_keystore(PW, FAST_TEST_PARAMS)
    return keystore, unlocked


def test_keystore_contains_no_plaintext_secrets():
    keystore, unlocked = make()
    text = repr(keystore)
    assert envelope.b64e(unlocked.kek) not in text
    assert envelope.b64e(unlocked.secret_keys[1]) not in text


def test_unlock_right_and_wrong_passphrase():
    keystore, original = make()
    again = envelope.unlock(keystore, PW)
    assert again.secret_keys == original.secret_keys
    with pytest.raises(InvalidPassphrase):
        envelope.unlock(keystore, "wrong passphrase!!")


def test_seal_and_open_roundtrip():
    keystore, unlocked = make()
    version, pk = envelope.active_public_key(keystore)
    sealed = envelope.seal_file(pk, FID, "notes.txt", b"hello")
    name, data = envelope.open_file(unlocked.secret_keys[version], FID, sealed.blob, sealed.wrapped_dek, sealed.enc_name)
    assert (name, data) == ("notes.txt", b"hello")
    assert b"hello" not in sealed.blob


def test_every_file_gets_its_own_key():
    keystore, _ = make()
    _, pk = envelope.active_public_key(keystore)
    a = envelope.seal_file(pk, FID, "a", b"same")
    b = envelope.seal_file(pk, FID, "a", b"same")
    assert a.wrapped_dek != b.wrapped_dek and a.blob != b.blob


def test_blob_cannot_be_moved_to_another_file_id():
    keystore, unlocked = make()
    version, pk = envelope.active_public_key(keystore)
    sealed = envelope.seal_file(pk, FID, "a", b"data")
    with pytest.raises(IntegrityError):
        envelope.open_file(unlocked.secret_keys[version], "1" * 32, sealed.blob, sealed.wrapped_dek, sealed.enc_name)


def test_tampered_blob_detected():
    keystore, unlocked = make()
    version, pk = envelope.active_public_key(keystore)
    sealed = envelope.seal_file(pk, FID, "a", b"data")
    bad = bytearray(sealed.blob)
    bad[-1] ^= 1
    with pytest.raises(IntegrityError):
        envelope.open_file(unlocked.secret_keys[version], FID, bytes(bad), sealed.wrapped_dek, sealed.enc_name)


def test_change_passphrase_keeps_keys_and_changes_kek():
    keystore, unlocked = make()
    new_ks, new_unlocked = envelope.change_passphrase(keystore, unlocked, "brand new passphrase", FAST_TEST_PARAMS)
    assert new_unlocked.kek != unlocked.kek
    assert envelope.unlock(new_ks, "brand new passphrase").secret_keys == unlocked.secret_keys
    with pytest.raises(InvalidPassphrase):
        envelope.unlock(new_ks, PW)
    assert new_ks["kdf"]["salt"] != keystore["kdf"]["salt"]


def test_add_version_and_rewrap():
    keystore, unlocked = make()
    _, pk1 = envelope.active_public_key(keystore)
    sealed = envelope.seal_file(pk1, FID, "a", b"data")
    ks2, un2 = envelope.add_key_version(keystore, unlocked)
    v2, pk2 = envelope.active_public_key(ks2)
    assert v2 == 2
    new_wrapped = envelope.rewrap_dek(un2.secret_keys[1], pk2, FID, sealed.wrapped_dek)
    _, data = envelope.open_file(un2.secret_keys[2], FID, sealed.blob, new_wrapped, sealed.enc_name)
    assert data == b"data"
    ks3, un3 = envelope.drop_unused_versions(ks2, un2, in_use={2})
    assert [k["version"] for k in ks3["keys"]] == [2] and set(un3.secret_keys) == {2}
