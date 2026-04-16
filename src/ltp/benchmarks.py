"""
Cryptographic benchmarking framework for the Lattice Transfer Protocol.

Provides comparative benchmarks across security levels and hash functions:
  - Key generation (ML-KEM + ML-DSA) at Level 3 vs Level 5
  - SealedBox seal/unseal at Level 3 vs Level 5
  - Hash throughput: SHA3-256 vs SHA-384 vs SHA-512
  - AEAD encrypt/decrypt at various payload sizes
  - Erasure encode/decode at various parameters
  - Full protocol round-trip (COMMIT → LATTICE → MATERIALIZE)

Reference: NIST PQC Round 3, CNSA 2.0 migration timeline
"""

from __future__ import annotations

import statistics
import time
from dataclasses import dataclass, field
from typing import Optional

from .primitives import (
    AEAD, MLKEM, MLDSA,
    SecurityProfile, HashFunction,
    get_security_profile, set_security_profile,
    internal_hash_bytes,
)
from .keypair import KeyPair, SealedBox
from .erasure import ErasureCoder
from .shards import ShardEncryptor

__all__ = [
    "BenchmarkResult",
    "CryptoBenchmark",
]

# FIPS-approved hashes valid for canonical lane benchmarks
_CANONICAL_HASHES = [HashFunction.SHA3_256, HashFunction.SHA_384, HashFunction.SHA_512]


@dataclass
class BenchmarkResult:
    """Result of a single benchmark run."""
    operation: str
    level: int
    hash_fn: str
    iterations: int
    mean_us: float
    std_us: float
    min_us: float
    max_us: float
    throughput_ops_sec: float
    metadata: dict = field(default_factory=dict)

    def summary_line(self) -> str:
        return (
            f"{self.operation:<40} L{self.level} {self.hash_fn:<12} "
            f"mean={self.mean_us:>10.1f}us  std={self.std_us:>8.1f}us  "
            f"({self.throughput_ops_sec:>8.0f} ops/s)"
        )


def _bench(fn, iterations: int) -> list[float]:
    """Run fn() for `iterations` and return list of elapsed microseconds."""
    times = []
    for _ in range(iterations):
        t0 = time.perf_counter_ns()
        fn()
        elapsed_ns = time.perf_counter_ns() - t0
        times.append(elapsed_ns / 1000.0)
    return times


def _make_result(
    operation: str,
    level: int,
    hash_fn: str,
    times_us: list[float],
    metadata: dict | None = None,
) -> BenchmarkResult:
    n = len(times_us)
    mean = statistics.mean(times_us)
    std = statistics.stdev(times_us) if n > 1 else 0.0
    return BenchmarkResult(
        operation=operation,
        level=level,
        hash_fn=hash_fn,
        iterations=n,
        mean_us=mean,
        std_us=std,
        min_us=min(times_us),
        max_us=max(times_us),
        throughput_ops_sec=1_000_000.0 / mean if mean > 0 else 0.0,
        metadata=metadata or {},
    )


class CryptoBenchmark:
    """Comparative cryptographic benchmark suite for LTP."""

    def __init__(self, iterations: int = 100) -> None:
        self.iterations = iterations

    def bench_keygen(
        self, level: int = 3, hash_fn: HashFunction = HashFunction.SHA3_256,
    ) -> BenchmarkResult:
        """Benchmark ML-KEM + ML-DSA key generation."""
        prev = set_security_profile(SecurityProfile(level, hash_fn=hash_fn))
        try:
            times = _bench(lambda: KeyPair.generate(label="bench"), self.iterations)
        finally:
            set_security_profile(prev)

        profile = SecurityProfile(level, hash_fn=hash_fn)
        return _make_result(
            "keygen (KEM+DSA)",
            level, hash_fn.value, times,
            {"ek_size": profile.kem_ek_size, "vk_size": profile.dsa_vk_size},
        )

    def bench_seal_unseal(
        self, level: int = 3, hash_fn: HashFunction = HashFunction.SHA3_256,
    ) -> BenchmarkResult:
        """Benchmark SealedBox seal + unseal round-trip."""
        prev = set_security_profile(SecurityProfile(level, hash_fn=hash_fn))
        try:
            kp = KeyPair.generate(label="bench-seal")
            payload = b"benchmark-payload-" + b"X" * 128

            def seal_unseal():
                sealed = SealedBox.seal(payload, kp.ek)
                SealedBox.unseal(sealed, kp)

            times = _bench(seal_unseal, self.iterations)
        finally:
            set_security_profile(prev)

        return _make_result("seal+unseal", level, hash_fn.value, times)

    def bench_hash(
        self, hash_fn: HashFunction = HashFunction.SHA3_256,
        payload_size: int = 1024,
    ) -> BenchmarkResult:
        """Benchmark hash throughput at a given payload size (internal lane)."""
        prev = set_security_profile(SecurityProfile(3, hash_fn=hash_fn,
                                                     internal_hash=hash_fn))
        try:
            data = b"B" * payload_size
            times = _bench(lambda: internal_hash_bytes(data), self.iterations)
        finally:
            set_security_profile(prev)

        mean_us = statistics.mean(times)
        throughput_mbs = (payload_size / (mean_us / 1_000_000.0)) / (1024 * 1024) if mean_us > 0 else 0.0
        return _make_result(
            f"hash ({payload_size}B)", 3, hash_fn.value, times,
            {"payload_size": payload_size, "throughput_mb_s": round(throughput_mbs, 2)},
        )

    def bench_aead(
        self, payload_size: int = 1024,
        hash_fn: HashFunction = HashFunction.SHA3_256,
    ) -> BenchmarkResult:
        """Benchmark AEAD encrypt + decrypt."""
        prev = set_security_profile(SecurityProfile(3, hash_fn=hash_fn))
        try:
            import os
            key = os.urandom(32)
            nonce = os.urandom(AEAD.NONCE_SIZE)
            plaintext = b"A" * payload_size

            def encrypt_decrypt():
                ct = AEAD.encrypt(key, plaintext, nonce)
                AEAD.decrypt(key, ct, nonce)

            times = _bench(encrypt_decrypt, self.iterations)
        finally:
            set_security_profile(prev)

        return _make_result(
            f"aead enc+dec ({payload_size}B)", 3, hash_fn.value, times,
            {"payload_size": payload_size},
        )

    def bench_erasure(
        self, data_size: int = 4096, n: int = 8, k: int = 4,
    ) -> BenchmarkResult:
        """Benchmark erasure encode + decode."""
        data = b"E" * data_size

        def encode_decode():
            shards = ErasureCoder.encode(data, n, k)
            shard_map = {i: shards[i] for i in range(k)}
            ErasureCoder.decode(shard_map, n, k)

        times = _bench(encode_decode, self.iterations)
        return _make_result(
            f"erasure enc+dec ({data_size}B n={n} k={k})",
            3, "n/a", times,
            {"data_size": data_size, "n": n, "k": k},
        )

    def bench_protocol_roundtrip(
        self, level: int = 3, hash_fn: HashFunction = HashFunction.SHA3_256,
        payload_size: int = 1024,
    ) -> BenchmarkResult:
        """Benchmark full COMMIT → LATTICE → MATERIALIZE round-trip."""
        from .commitment import CommitmentNetwork, CommitmentNode
        from .entity import Entity
        from .protocol import LTPProtocol

        prev = set_security_profile(SecurityProfile(level, hash_fn=hash_fn))
        try:
            network = CommitmentNetwork()
            for i in range(6):
                network.add_node(f"bench-{i}", f"us-east-{i % 3}")
            protocol = LTPProtocol(network)
            alice = KeyPair.generate(label="bench-alice")
            bob = KeyPair.generate(label="bench-bob")
            content = b"P" * payload_size

            def roundtrip():
                entity = Entity(content=content, shape="application/octet-stream")
                eid, record, cek = protocol.commit(entity, alice)
                sealed = protocol.lattice(eid, record, cek, bob)
                protocol.materialize(sealed, bob)

            times = _bench(roundtrip, min(self.iterations, 20))
        finally:
            set_security_profile(prev)

        return _make_result(
            f"protocol roundtrip ({payload_size}B)",
            level, hash_fn.value, times,
            {"payload_size": payload_size},
        )

    def run_all(self) -> list[BenchmarkResult]:
        """Run the full benchmark suite across levels and FIPS-approved hash functions."""
        results = []

        for level in (3, 5):
            for hf in _CANONICAL_HASHES:
                results.append(self.bench_keygen(level, hf))
                results.append(self.bench_seal_unseal(level, hf))

        for hf in HashFunction:
            for size in (1024, 65536):
                results.append(self.bench_hash(hf, size))

        for hf in _CANONICAL_HASHES:
            results.append(self.bench_aead(1024, hf))

        for n, k in [(8, 4), (16, 8)]:
            results.append(self.bench_erasure(4096, n, k))

        for level in (3, 5):
            results.append(self.bench_protocol_roundtrip(level, HashFunction.SHA3_256, 1024))

        return results

    @staticmethod
    def format_report(results: list[BenchmarkResult]) -> str:
        """Format benchmark results as a human-readable report."""
        lines = [
            "=" * 100,
            "LTP Cryptographic Benchmark Report",
            "=" * 100,
            "",
            f"{'Operation':<40} {'Level':<6} {'Hash':<12} "
            f"{'Mean (us)':>10} {'Std (us)':>10} {'Ops/sec':>10}",
            "-" * 100,
        ]

        for r in results:
            lines.append(r.summary_line())

        lines.append("-" * 100)

        l3 = [r for r in results if r.level == 3 and r.operation == "keygen (KEM+DSA)"]
        l5 = [r for r in results if r.level == 5 and r.operation == "keygen (KEM+DSA)"]
        if l3 and l5:
            overhead = (l5[0].mean_us / l3[0].mean_us - 1) * 100
            lines.append(f"\nLevel 5 keygen overhead vs Level 3: {overhead:+.1f}%")

        l3_seal = [r for r in results if r.level == 3 and r.operation == "seal+unseal"]
        l5_seal = [r for r in results if r.level == 5 and r.operation == "seal+unseal"]
        if l3_seal and l5_seal:
            overhead = (l5_seal[0].mean_us / l3_seal[0].mean_us - 1) * 100
            lines.append(f"Level 5 seal+unseal overhead vs Level 3: {overhead:+.1f}%")

        lines.append("")
        return "\n".join(lines)
