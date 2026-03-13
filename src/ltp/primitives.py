"""
Cryptographic primitives for the Lattice Transfer Protocol.

Provides:
  - SecurityProfile — configurable security levels (Level 3 / Level 5)
  - HashFunction    — pluggable hash: BLAKE2b-256, SHA-384, SHA-512
  - H()       — content-addressing hash (algorithm-prefixed string)
  - H_bytes() — content-addressing hash (raw bytes, for internal operations)
  - AEAD      — authenticated encryption (PoC: keystream + HMAC tag)
  - MLKEM     — ML-KEM key encapsulation (PoC simulation, FIPS 203)
  - MLDSA     — ML-DSA digital signatures (PoC simulation, FIPS 204)

Production replacement:
  AEAD  → XChaCha20-Poly1305 (libsodium/NaCl)
  MLKEM → liboqs ML-KEM-768/1024 or FIPS 203 implementation
  MLDSA → liboqs ML-DSA-65/87 or FIPS 204 implementation
"""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
import os
import struct
from enum import Enum
from typing import Optional

__all__ = [
    "SecurityProfile", "HashFunction",
    "H", "H_bytes", "AEAD", "MLKEM", "MLDSA",
    "get_security_profile", "set_security_profile",
]


# ---------------------------------------------------------------------------
# HashFunction: pluggable hash for FIPS/CNSA 2.0 compliance (§7.1)
# ---------------------------------------------------------------------------

class HashFunction(Enum):
    """
    Supported hash functions.

    BLAKE2b-256: Default PoC hash (fast, 256-bit, not FIPS-standardized)
    SHA_384:     FIPS 180-4, CNSA 2.0 approved, 384-bit output
    SHA_512:     FIPS 180-4, CNSA 2.0 approved, 512-bit output
    """
    BLAKE2B_256 = "blake2b"
    SHA_384 = "sha384"
    SHA_512 = "sha512"


def _hash_digest(data: bytes, algo: HashFunction, raw: bool = False):
    """Compute hash with the specified algorithm."""
    if algo == HashFunction.BLAKE2B_256:
        d = hashlib.blake2b(data, digest_size=32)
        prefix = "blake2b"
        digest_bytes = d.digest()
    elif algo == HashFunction.SHA_384:
        d = hashlib.sha384(data)
        prefix = "sha384"
        digest_bytes = d.digest()  # 48 bytes
    elif algo == HashFunction.SHA_512:
        d = hashlib.sha512(data)
        prefix = "sha512"
        digest_bytes = d.digest()  # 64 bytes
    else:
        raise ValueError(f"Unsupported hash function: {algo}")

    if raw:
        return digest_bytes
    return f"{prefix}:{d.hexdigest()}"


# ---------------------------------------------------------------------------
# SecurityProfile: configurable NIST security levels (§7.2)
# ---------------------------------------------------------------------------

class SecurityProfile:
    """
    Configurable security parameter set for LTP.

    Level 3 (default): ML-KEM-768 + ML-DSA-65 — NIST Level 3 (~AES-192)
      Meets civilian federal, PCI DSS, SOC 2, HIPAA, FedRAMP, GDPR, eIDAS.

    Level 5: ML-KEM-1024 + ML-DSA-87 — NIST Level 5 (~AES-256)
      Required for CNSA 2.0 / NSS / DoD IL5+ by January 2027.

    Each profile specifies:
      - KEM parameters (ek, dk, ct, ss sizes)
      - DSA parameters (vk, sk, sig sizes)
      - Hash function (BLAKE2b-256 or SHA-384/512)
      - Security level label
    """

    def __init__(
        self,
        level: int = 3,
        hash_fn: HashFunction = HashFunction.BLAKE2B_256,
    ) -> None:
        if level not in (3, 5):
            raise ValueError(f"Security level must be 3 or 5, got {level}")

        self.level = level
        self.hash_fn = hash_fn

        if level == 3:
            # ML-KEM-768 (FIPS 203)
            self.kem_ek_size = 1184
            self.kem_dk_size = 2400
            self.kem_ct_size = 1088
            self.kem_ss_size = 32
            # ML-DSA-65 (FIPS 204)
            self.dsa_vk_size = 1952
            self.dsa_sk_size = 4032
            self.dsa_sig_size = 3309
        else:  # level == 5
            # ML-KEM-1024 (FIPS 203)
            self.kem_ek_size = 1568
            self.kem_dk_size = 3168
            self.kem_ct_size = 1568
            self.kem_ss_size = 32
            # ML-DSA-87 (FIPS 204)
            self.dsa_vk_size = 2592
            self.dsa_sk_size = 4896
            self.dsa_sig_size = 4627

    @property
    def label(self) -> str:
        return f"Level-{self.level}/{self.hash_fn.value}"

    def __repr__(self) -> str:
        return (
            f"SecurityProfile(level={self.level}, "
            f"hash={self.hash_fn.value}, "
            f"kem_ek={self.kem_ek_size}B, dsa_vk={self.dsa_vk_size}B)"
        )

    # Convenience constructors
    @classmethod
    def level3(cls, hash_fn: HashFunction = HashFunction.BLAKE2B_256):
        """NIST Level 3: ML-KEM-768 + ML-DSA-65 (civilian/commercial)."""
        return cls(level=3, hash_fn=hash_fn)

    @classmethod
    def level5(cls, hash_fn: HashFunction = HashFunction.SHA_384):
        """NIST Level 5: ML-KEM-1024 + ML-DSA-87 (CNSA 2.0 / NSS)."""
        return cls(level=5, hash_fn=hash_fn)

    @classmethod
    def cnsa2(cls):
        """CNSA 2.0 Suite: Level 5 + SHA-384 (NSA requirement by 2027)."""
        return cls(level=5, hash_fn=HashFunction.SHA_384)


# Module-level active profile (default: Level 3 / BLAKE2b)
_active_profile: SecurityProfile = SecurityProfile.level3()


def get_security_profile() -> SecurityProfile:
    """Get the active security profile."""
    return _active_profile


def set_security_profile(profile: SecurityProfile) -> SecurityProfile:
    """
    Set the active security profile. Returns the previous profile.

    WARNING: Changing the profile mid-session will cause key size mismatches
    with existing keys. Only call this at initialization time.
    """
    global _active_profile
    previous = _active_profile
    _active_profile = profile
    # Update MLKEM/MLDSA class-level sizes to match
    MLKEM._sync_profile(profile)
    MLDSA._sync_profile(profile)
    return previous


# ---------------------------------------------------------------------------
# Hash functions (use active profile's hash algorithm)
# ---------------------------------------------------------------------------

def H(data: bytes) -> str:
    """Content-addressing hash. Returns '<algo>:<hex>' string.

    Canonical format per whitepaper §1.2: algorithm-prefixed hex string.
    The algorithm is determined by the active SecurityProfile.
    Prefix makes the algorithm explicit and allows negotiation of alternatives.
    """
    return _hash_digest(data, _active_profile.hash_fn)


def H_bytes(data: bytes) -> bytes:
    """Content-addressing hash. Returns raw bytes (no prefix).

    Used internally where binary output is required (keystream, nonces, tags).
    Output size depends on hash function: 32B (BLAKE2b), 48B (SHA-384), 64B (SHA-512).
    """
    return _hash_digest(data, _active_profile.hash_fn, raw=True)


# ---------------------------------------------------------------------------
# AEAD: Authenticated Encryption with Associated Data
#
# PoC implementation using BLAKE2b-derived keystream + XOR + HMAC tag.
# Production: XChaCha20-Poly1305 via libsodium/NaCl.
# ---------------------------------------------------------------------------

class AEAD:
    """
    Authenticated encryption for shard-level and envelope-level encryption.

    Provides:
      - Confidentiality: XOR with BLAKE2b-derived keystream
      - Integrity: 32-byte authentication tag (forgery → ValueError)
      - Nonce binding: each (key, nonce) pair produces a unique keystream

    Each shard is encrypted with a nonce derived as H(CEK || entity_id || shard_index)[:16],
    binding nonce uniqueness to both key and entity identity.
    """

    TAG_SIZE = 32  # Default; actual tag size = len(H_bytes(b""))

    @classmethod
    def _tag_size(cls) -> int:
        """Actual tag size based on active hash function."""
        return len(H_bytes(b"tag-size-probe"))

    @staticmethod
    def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
        """Generate deterministic keystream: BLAKE2b(key || nonce || counter)."""
        stream = bytearray()
        counter = 0
        while len(stream) < length:
            block = key + nonce + struct.pack('>Q', counter)
            stream.extend(H_bytes(block))
            counter += 1
        return bytes(stream[:length])

    @staticmethod
    def _compute_tag(key: bytes, ciphertext: bytes, nonce: bytes) -> bytes:
        """Compute authentication tag: BLAKE2b(tag_key || nonce || ciphertext)."""
        tag_key = H_bytes(key + b"aead-auth-tag-key")
        return H_bytes(tag_key + nonce + ciphertext)

    @classmethod
    def encrypt(cls, key: bytes, plaintext: bytes, nonce: bytes) -> bytes:
        """
        Encrypt plaintext → ciphertext || 32-byte auth tag.

        Args:
            key: 32-byte symmetric key
            plaintext: data to encrypt
            nonce: unique per (key, message) pair
        """
        keystream = cls._keystream(key, nonce, len(plaintext))
        ciphertext = bytes(a ^ b for a, b in zip(plaintext, keystream))
        tag = cls._compute_tag(key, ciphertext, nonce)
        return ciphertext + tag

    @classmethod
    def decrypt(cls, key: bytes, ciphertext_with_tag: bytes, nonce: bytes) -> bytes:
        """
        Verify tag, then decrypt → plaintext. Raises ValueError if tampered.

        IMPORTANT: Tag is verified BEFORE decryption (authenticate-then-decrypt).
        """
        tag_size = cls._tag_size()
        if len(ciphertext_with_tag) < tag_size:
            raise ValueError("Ciphertext too short (missing authentication tag)")

        ciphertext = ciphertext_with_tag[:-tag_size]
        tag = ciphertext_with_tag[-tag_size:]

        expected_tag = cls._compute_tag(key, ciphertext, nonce)
        if not hmac_mod.compare_digest(tag, expected_tag):
            raise ValueError("AEAD authentication FAILED — data has been tampered with")

        keystream = cls._keystream(key, nonce, len(ciphertext))
        return bytes(a ^ b for a, b in zip(ciphertext, keystream))


# ---------------------------------------------------------------------------
# ML-KEM (FIPS 203 / Kyber): Key Encapsulation Mechanism
#
# PoC SIMULATION: Uses hash-derived keystream to simulate ML-KEM with
# correct key sizes per active SecurityProfile:
#   Level 3 (ML-KEM-768):  ek=1184, dk=2400, ct=1088, ss=32
#   Level 5 (ML-KEM-1024): ek=1568, dk=3168, ct=1568, ss=32
#
# Production: Replace with liboqs ML-KEM or FIPS 203 implementation.
# The PoC enforces size constraints and API semantics; the math is simulated.
# ---------------------------------------------------------------------------

class MLKEM:
    """
    ML-KEM Key Encapsulation Mechanism — PoC simulation.

    Supports both ML-KEM-768 (Level 3) and ML-KEM-1024 (Level 5) via
    SecurityProfile. Key sizes are set by the active profile.

    Provides:
      - KeyGen() → (encapsulation_key, decapsulation_key)
      - Encaps(ek) → (shared_secret, ciphertext)
      - Decaps(dk, ciphertext) → shared_secret

    Security level: Determined by active SecurityProfile.
    """

    # Default Level 3 sizes (updated by _sync_profile)
    EK_SIZE = 1184   # Encapsulation key size (bytes)
    DK_SIZE = 2400   # Decapsulation key size (bytes)
    CT_SIZE = 1088   # Ciphertext size (bytes)
    SS_SIZE = 32     # Shared secret size (bytes)

    @classmethod
    def _sync_profile(cls, profile: SecurityProfile) -> None:
        """Sync class-level sizes with the active security profile."""
        cls.EK_SIZE = profile.kem_ek_size
        cls.DK_SIZE = profile.kem_dk_size
        cls.CT_SIZE = profile.kem_ct_size
        cls.SS_SIZE = profile.kem_ss_size

    @classmethod
    def keygen(cls) -> tuple[bytes, bytes]:
        """
        Generate an ML-KEM keypair (768 or 1024 depending on profile).

        Returns: (encapsulation_key, decapsulation_key)
        The ek is public; dk MUST remain secret.
        """
        seed = os.urandom(64)
        hash_size = len(H_bytes(b"size-probe"))

        dk_material = bytearray()
        for i in range(0, cls.DK_SIZE, hash_size):
            dk_material.extend(H_bytes(seed + struct.pack('>I', i) + b"mlkem-dk"))
        dk = bytes(dk_material[:cls.DK_SIZE])

        ek_material = bytearray()
        for i in range(0, cls.EK_SIZE, hash_size):
            ek_material.extend(H_bytes(seed + struct.pack('>I', i) + b"mlkem-ek"))
        ek = bytes(ek_material[:cls.EK_SIZE])

        return ek, dk

    @classmethod
    def encaps(cls, ek: bytes) -> tuple[bytes, bytes]:
        """
        Encapsulate: generate a shared secret and ciphertext.

        Args:
            ek: Encapsulation key (public key of receiver)
        Returns:
            (shared_secret, ciphertext) — ss is 32 bytes, ct size per profile

        The ciphertext is sent to the receiver; only the holder of dk can
        recover the shared secret from it. Each call produces a FRESH
        (shared_secret, ciphertext) pair — this is the basis for forward secrecy.
        """
        assert len(ek) == cls.EK_SIZE, f"Invalid ek size: {len(ek)} (expected {cls.EK_SIZE})"

        ephemeral = os.urandom(32)
        ss_raw = H_bytes(ek + ephemeral + b"mlkem-shared-secret")
        shared_secret = ss_raw[:32]  # Always 32-byte shared secret

        hash_size = len(ss_raw)
        ct_material = bytearray()
        for i in range(0, cls.CT_SIZE, hash_size):
            ct_material.extend(H_bytes(ek + ephemeral + struct.pack('>I', i) + b"mlkem-ct"))
        ciphertext = bytes(ct_material[:cls.CT_SIZE])

        return shared_secret, ciphertext

    @classmethod
    def decaps(cls, dk: bytes, ciphertext: bytes) -> bytes:
        """
        Decapsulate: recover shared secret from ciphertext using dk.

        PoC NOTE: In production ML-KEM, dk mathematically recovers the
        randomness embedded in the ciphertext via lattice decryption.
        The PoC simulates this via SealedBox._PoC_encaps_table.
        """
        assert len(dk) == cls.DK_SIZE, f"Invalid dk size: {len(dk)} (expected {cls.DK_SIZE})"
        assert len(ciphertext) == cls.CT_SIZE, f"Invalid ct size: {len(ciphertext)} (expected {cls.CT_SIZE})"
        raise NotImplementedError("Direct decaps() not used in PoC — see SealedBox")


# ---------------------------------------------------------------------------
# ML-DSA (FIPS 204 / Dilithium): Digital Signatures
#
# PoC SIMULATION: Uses hash-HMAC to simulate ML-DSA with correct sizes
# per active SecurityProfile:
#   Level 3 (ML-DSA-65): vk=1952, sk=4032, sig=3309
#   Level 5 (ML-DSA-87): vk=2592, sk=4896, sig=4627
#
# Production: Replace with liboqs ML-DSA or FIPS 204 implementation.
# ---------------------------------------------------------------------------

class MLDSA:
    """
    ML-DSA Digital Signature Algorithm — PoC simulation.

    Supports both ML-DSA-65 (Level 3) and ML-DSA-87 (Level 5) via
    SecurityProfile. Key/signature sizes are set by the active profile.

    Provides:
      - KeyGen() → (verification_key, signing_key)
      - Sign(sk, message) → signature
      - Verify(vk, message, signature) → bool

    Security level: Determined by active SecurityProfile.

    PoC simulation note:
      Signature verification uses a lookup table mapping
      (vk_fingerprint, message_hash) → expected_signature.
      keygen() stores the sk→vk binding; sign() stores the signature;
      verify() looks it up. Production replaces this with FIPS 204 math.
    """

    VK_SIZE = 1952   # Verification key (public) size
    SK_SIZE = 4032   # Signing key (private) size
    SIG_SIZE = 3309  # Signature size

    @classmethod
    def _sync_profile(cls, profile: SecurityProfile) -> None:
        """Sync class-level sizes with the active security profile."""
        cls.VK_SIZE = profile.dsa_vk_size
        cls.SK_SIZE = profile.dsa_sk_size
        cls.SIG_SIZE = profile.dsa_sig_size

    # PoC: maps sk_fingerprint → vk_fingerprint (populated by keygen)
    _PoC_sk_to_vk: dict[str, str] = {}
    # PoC: maps (vk_fingerprint, message_hash) → signature (populated by sign)
    _PoC_sig_table: dict[tuple[str, str], bytes] = {}

    @classmethod
    def keygen(cls) -> tuple[bytes, bytes]:
        """
        Generate an ML-DSA keypair (65 or 87 depending on profile).

        Returns: (verification_key, signing_key)
        """
        seed = os.urandom(64)
        hash_size = len(H_bytes(b"size-probe"))

        sk_material = bytearray()
        for i in range(0, cls.SK_SIZE, hash_size):
            sk_material.extend(H_bytes(seed + struct.pack('>I', i) + b"mldsa-sk"))
        sk = bytes(sk_material[:cls.SK_SIZE])

        vk_material = bytearray()
        for i in range(0, cls.VK_SIZE, hash_size):
            vk_material.extend(H_bytes(seed + struct.pack('>I', i) + b"mldsa-vk"))
        vk = bytes(vk_material[:cls.VK_SIZE])

        # PoC: store sk→vk binding for signature verification
        sk_fp = H(sk[:32])
        vk_fp = H(vk)
        cls._PoC_sk_to_vk[sk_fp] = vk_fp

        return vk, sk

    @classmethod
    def sign(cls, sk: bytes, message: bytes) -> bytes:
        """
        Sign a message with sk.

        Returns: signature (size depends on active profile)
        """
        assert len(sk) == cls.SK_SIZE, f"Invalid sk size: {len(sk)} (expected {cls.SK_SIZE})"

        raw_sig = H_bytes(sk[:32] + message + b"mldsa-signature")
        hash_size = len(raw_sig)
        sig_material = bytearray()
        for i in range(0, cls.SIG_SIZE, hash_size):
            sig_material.extend(H_bytes(raw_sig + struct.pack('>I', i) + b"mldsa-expand"))
        signature = bytes(sig_material[:cls.SIG_SIZE])

        # PoC: store for verification lookup
        sk_fp = H(sk[:32])
        vk_fp = cls._PoC_sk_to_vk.get(sk_fp)
        if vk_fp is not None:
            msg_hash = H(message)
            cls._PoC_sig_table[(vk_fp, msg_hash)] = signature

        return signature

    @classmethod
    def verify(cls, vk: bytes, message: bytes, signature: bytes) -> bool:
        """
        Verify a signature against vk and message.

        Returns: True if valid, False if forgery/tamper detected.
        """
        assert len(vk) == cls.VK_SIZE, f"Invalid vk size: {len(vk)} (expected {cls.VK_SIZE})"
        if len(signature) != cls.SIG_SIZE:
            return False
        vk_fp = H(vk)
        msg_hash = H(message)
        expected = cls._PoC_sig_table.get((vk_fp, msg_hash))
        if expected is None:
            return False
        return hmac_mod.compare_digest(expected, signature)
