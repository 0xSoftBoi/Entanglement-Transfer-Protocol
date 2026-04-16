from src.ltp.backends import BackendConfig, create_backend, resolve_backend_type
from src.ltp.backends.ethereum import EthereumLiveBackend, EthereumSimulatedBackend
from src.ltp.backends.monad_l1 import MonadL1Backend


def test_resolve_legacy_ethereum_to_simulated_without_live_config():
    config = BackendConfig(backend_type="ethereum")

    assert resolve_backend_type(config) == "ethereum-sim"
    assert isinstance(create_backend(config), EthereumSimulatedBackend)


def test_resolve_legacy_ethereum_to_live_with_full_live_config():
    config = BackendConfig(
        backend_type="ethereum",
        rpc_url="https://rpc.example",
        contract_address="0x1234",
        operator_private_key="0xabc",
    )

    assert resolve_backend_type(config) == "ethereum-live"


def test_explicit_ethereum_live_requires_full_live_config():
    config = BackendConfig(backend_type="ethereum-live", rpc_url="https://rpc.example")

    try:
        create_backend(config)
    except ValueError as exc:
        assert "ethereum-live requires" in str(exc)
    else:
        raise AssertionError("ethereum-live should reject incomplete live config")


def test_explicit_ethereum_sim_rejects_live_fields():
    config = BackendConfig(
        backend_type="ethereum-sim",
        rpc_url="https://rpc.example",
    )

    try:
        create_backend(config)
    except ValueError as exc:
        assert "ethereum-sim must not be configured" in str(exc)
    else:
        raise AssertionError("ethereum-sim should reject live adapter fields")


def test_explicit_monad_sim_backend_type():
    config = BackendConfig(backend_type="monad-l1-sim")

    assert resolve_backend_type(config) == "monad-l1-sim"
    assert isinstance(create_backend(config), MonadL1Backend)


def test_legacy_monad_alias_resolves_to_simulated_backend():
    config = BackendConfig(backend_type="monad-l1")

    assert resolve_backend_type(config) == "monad-l1-sim"
    assert isinstance(create_backend(config), MonadL1Backend)

