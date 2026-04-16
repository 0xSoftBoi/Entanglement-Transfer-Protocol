"""Tests for the LTP cryptographic benchmarking framework."""

import pytest

from src.ltp.benchmarks import BenchmarkResult, CryptoBenchmark
from src.ltp.primitives import (
    SecurityProfile, HashFunction,
    get_security_profile, set_security_profile,
)


@pytest.fixture(autouse=True)
def restore_default_profile():
    prev = get_security_profile()
    yield
    set_security_profile(prev)


# ---------------------------------------------------------------------------
# BenchmarkResult
# ---------------------------------------------------------------------------

class TestBenchmarkResult:
    def test_summary_line_format(self):
        r = BenchmarkResult(
            operation="test_op", level=3, hash_fn="sha3-256",
            iterations=100, mean_us=500.0, std_us=10.0,
            min_us=480.0, max_us=520.0, throughput_ops_sec=2000.0,
        )
        line = r.summary_line()
        assert "test_op" in line
        assert "L3" in line
        assert "sha3-256" in line
        assert "500.0" in line

    def test_metadata_stored(self):
        r = BenchmarkResult(
            operation="test", level=5, hash_fn="sha384",
            iterations=10, mean_us=100.0, std_us=5.0,
            min_us=90.0, max_us=110.0, throughput_ops_sec=10000.0,
            metadata={"key_size": 1568},
        )
        assert r.metadata["key_size"] == 1568


# ---------------------------------------------------------------------------
# Key Generation Benchmarks
# ---------------------------------------------------------------------------

class TestKeygenBenchmark:
    def test_keygen_level3(self):
        bench = CryptoBenchmark(iterations=5)
        result = bench.bench_keygen(level=3)
        assert result.operation == "keygen (KEM+DSA)"
        assert result.level == 3
        assert result.iterations == 5
        assert result.mean_us > 0
        assert result.throughput_ops_sec > 0

    def test_keygen_level5(self):
        bench = CryptoBenchmark(iterations=5)
        result = bench.bench_keygen(level=5, hash_fn=HashFunction.SHA_384)
        assert result.level == 5
        assert result.mean_us > 0
        assert result.metadata["ek_size"] == 1568  # ML-KEM-1024

    def test_keygen_level5_larger_keys(self):
        bench = CryptoBenchmark(iterations=5)
        r3 = bench.bench_keygen(level=3)
        r5 = bench.bench_keygen(level=5, hash_fn=HashFunction.SHA_384)
        assert r5.metadata["ek_size"] > r3.metadata["ek_size"]
        assert r5.metadata["vk_size"] > r3.metadata["vk_size"]


# ---------------------------------------------------------------------------
# Seal/Unseal Benchmarks
# ---------------------------------------------------------------------------

class TestSealUnsealBenchmark:
    def test_seal_unseal_level3(self):
        bench = CryptoBenchmark(iterations=5)
        result = bench.bench_seal_unseal(level=3)
        assert result.operation == "seal+unseal"
        assert result.level == 3
        assert result.mean_us > 0

    def test_seal_unseal_level5(self):
        bench = CryptoBenchmark(iterations=5)
        result = bench.bench_seal_unseal(level=5, hash_fn=HashFunction.SHA_384)
        assert result.level == 5
        assert result.mean_us > 0

    def test_seal_unseal_sha384(self):
        bench = CryptoBenchmark(iterations=5)
        result = bench.bench_seal_unseal(level=3, hash_fn=HashFunction.SHA_384)
        assert result.hash_fn == "sha384"

    def test_seal_unseal_sha512(self):
        bench = CryptoBenchmark(iterations=5)
        result = bench.bench_seal_unseal(level=5, hash_fn=HashFunction.SHA_512)
        assert result.hash_fn == "sha512"
        assert result.level == 5


# ---------------------------------------------------------------------------
# Hash Benchmarks (internal lane — supports all hash functions)
# ---------------------------------------------------------------------------

class TestHashBenchmark:
    def test_hash_blake3(self):
        bench = CryptoBenchmark(iterations=10)
        result = bench.bench_hash(HashFunction.BLAKE3_256, 1024)
        assert "hash" in result.operation
        assert result.mean_us > 0
        assert result.metadata["payload_size"] == 1024

    def test_hash_sha384(self):
        bench = CryptoBenchmark(iterations=10)
        result = bench.bench_hash(HashFunction.SHA_384, 65536)
        assert result.hash_fn == "sha384"
        assert result.metadata["throughput_mb_s"] > 0

    def test_hash_sha512(self):
        bench = CryptoBenchmark(iterations=10)
        result = bench.bench_hash(HashFunction.SHA_512, 1024)
        assert result.hash_fn == "sha512"


# ---------------------------------------------------------------------------
# AEAD Benchmarks
# ---------------------------------------------------------------------------

class TestAEADBenchmark:
    def test_aead_1kb(self):
        bench = CryptoBenchmark(iterations=10)
        result = bench.bench_aead(1024)
        assert "aead" in result.operation
        assert result.mean_us > 0

    def test_aead_64kb(self):
        bench = CryptoBenchmark(iterations=5)
        result = bench.bench_aead(65536)
        assert result.metadata["payload_size"] == 65536


# ---------------------------------------------------------------------------
# Erasure Benchmarks
# ---------------------------------------------------------------------------

class TestErasureBenchmark:
    def test_erasure_8_4(self):
        bench = CryptoBenchmark(iterations=5)
        result = bench.bench_erasure(4096, 8, 4)
        assert "erasure" in result.operation
        assert result.mean_us > 0

    def test_erasure_16_8(self):
        bench = CryptoBenchmark(iterations=3)
        result = bench.bench_erasure(4096, 16, 8)
        assert result.metadata["n"] == 16
        assert result.metadata["k"] == 8


# ---------------------------------------------------------------------------
# Protocol Round-trip Benchmarks
# ---------------------------------------------------------------------------

class TestProtocolRoundtripBenchmark:
    def test_roundtrip_level3(self):
        bench = CryptoBenchmark(iterations=3)
        result = bench.bench_protocol_roundtrip(level=3, payload_size=512)
        assert "protocol roundtrip" in result.operation
        assert result.level == 3
        assert result.mean_us > 0

    def test_roundtrip_level5(self):
        bench = CryptoBenchmark(iterations=3)
        result = bench.bench_protocol_roundtrip(
            level=5, hash_fn=HashFunction.SHA_384, payload_size=512,
        )
        assert result.level == 5


# ---------------------------------------------------------------------------
# Report Generation
# ---------------------------------------------------------------------------

class TestBenchmarkReport:
    def test_run_all_returns_results(self):
        bench = CryptoBenchmark(iterations=3)
        results = bench.run_all()
        assert len(results) > 10
        assert all(isinstance(r, BenchmarkResult) for r in results)

    def test_format_report(self):
        bench = CryptoBenchmark(iterations=3)
        results = bench.run_all()
        report = CryptoBenchmark.format_report(results)
        assert "LTP Cryptographic Benchmark Report" in report
        assert "Level 5 keygen overhead" in report
        assert "seal+unseal" in report

    def test_all_results_have_positive_throughput(self):
        bench = CryptoBenchmark(iterations=3)
        results = bench.run_all()
        for r in results:
            assert r.throughput_ops_sec > 0, f"{r.operation} has zero throughput"
            assert r.mean_us > 0, f"{r.operation} has zero mean"
