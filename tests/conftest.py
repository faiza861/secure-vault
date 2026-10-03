import pytest

from securevault.core.kdf import FAST_TEST_PARAMS
from securevault.storage.memory import MemoryBackend
from securevault.storage.vault import Vault

PASSPHRASE = "correct horse battery staple"


class FakeClock:
    """Controllable clock so tests can place events at exact times."""

    def __init__(self, start: float = 1_760_000_000.0):
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def backend():
    return MemoryBackend()


@pytest.fixture
def vault(backend, clock):
    return Vault.initialize(backend, PASSPHRASE, kdf_params=FAST_TEST_PARAMS, clock=clock)
