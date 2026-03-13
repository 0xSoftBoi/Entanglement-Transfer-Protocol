"""
Tests for enterprise/government compliance features (§7).

Covers:
  1. SecurityProfile: configurable Level 3 / Level 5 parameter sets
  2. HashFunction: pluggable BLAKE2b-256, SHA-384, SHA-512
  3. HSMBackend / SoftwareHSM: key management interface for regulated environments
  4. End-to-end: full protocol under Level 5 / SHA-384 / HSM
"""

import pytest

from src.ltp.primitives import (
    H,
    H_bytes,
    AEAD,
    MLKEM,
    MLDSA,
    SecurityProfile,
    HashFunction,
    get_security_profile,
    set_security_profile,
)
from src.ltp.keypair import KeyPair, SealedBox
from src.ltp.hsm import HSMBackend, SoftwareHSM
from src.ltp.entity import Entity
from src.ltp.commitment import CommitmentNetwork
from src.ltp.protocol import LTPProtocol


# ---------------------------------------------------------------------------
# Helpers: save/restore profile to avoid cross-test contamination
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def restore_default_profile():
    """Ensure every test starts and ends with the default Level 3 profile."""
    original = get_security_profile()
    set_security_profile(SecurityProfile.level3())
    yield
    set_security_profile(original)


# ===========================================================================
# 1. SECURITY PROFILE (§7.2)
# ===========================================================================

class TestSecurityProfileConstruction:
    def test_level3_defaults(self):
        p = SecurityProfile.level3()
        assert p.level == 3
        assert p.hash_fn == HashFunction.BLAKE2B_256
        assert p.kem_ek_size == 1184
        assert p.kem_dk_size == 2400
        assert p.kem_ct_size == 1088
        assert p.dsa_vk_size == 1952
        assert p.dsa_sk_size == 4032
        assert p.dsa_sig_size == 3309

    def test_level5_defaults(self):
        p = SecurityProfile.level5()
        assert p.level == 5
        assert p.hash_fn == HashFunction.SHA_384
        assert p.kem_ek_size == 1568
        assert p.kem_dk_size == 3168
        assert p.kem_ct_size == 1568
        assert p.dsa_vk_size == 2592
        assert p.dsa_sk_size == 4896
        assert p.dsa_sig_size == 4627

    def test_cnsa2_is_level5_sha384(self):
        p = SecurityProfile.cnsa2()
        assert p.level == 5
        assert p.hash_fn == HashFunction.SHA_384

    def test_invalid_level_raises(self):
        with pytest.raises(ValueError, match="must be 3 or 5"):
            SecurityProfile(level=4)

    def test_custom_hash_on_level3(self):
        p = SecurityProfile(level=3, hash_fn=HashFunction.SHA_512)
        assert p.level == 3
        assert p.hash_fn == HashFunction.SHA_512

    def test_label_format(self):
        p = SecurityProfile.level3()
        assert p.label == "Level-3/blake2b"
        p5 = SecurityProfile.cnsa2()
        assert p5.label == "Level-5/sha384"

    def test_repr(self):
        p = SecurityProfile.level3()
        r = repr(p)
        assert "level=3" in r
        assert "blake2b" in r


class TestSecurityProfileActivation:
    def test_default_is_level3(self):
        p = get_security_profile()
        assert p.level == 3

    def test_set_returns_previous(self):
        prev = set_security_profile(SecurityProfile.level5())
        assert prev.level == 3
        current = get_security_profile()
        assert current.level == 5

    def test_mlkem_sizes_sync_on_level5(self):
        set_security_profile(SecurityProfile.level5())
        assert MLKEM.EK_SIZE == 1568
        assert MLKEM.DK_SIZE == 3168
        assert MLKEM.CT_SIZE == 1568

    def test_mldsa_sizes_sync_on_level5(self):
        set_security_profile(SecurityProfile.level5())
        assert MLDSA.VK_SIZE == 2592
        assert MLDSA.SK_SIZE == 4896
        assert MLDSA.SIG_SIZE == 4627

    def test_sizes_revert_on_level3(self):
        set_security_profile(SecurityProfile.level5())
        set_security_profile(SecurityProfile.level3())
        assert MLKEM.EK_SIZE == 1184
        assert MLDSA.VK_SIZE == 1952


class TestLevel5KeyGeneration:
    def test_kem_keygen_level5_sizes(self):
        set_security_profile(SecurityProfile.level5())
        ek, dk = MLKEM.keygen()
        assert len(ek) == 1568
        assert len(dk) == 3168

    def test_dsa_keygen_level5_sizes(self):
        set_security_profile(SecurityProfile.level5())
        vk, sk = MLDSA.keygen()
        assert len(vk) == 2592
        assert len(sk) == 4896

    def test_kem_encaps_level5_ciphertext_size(self):
        set_security_profile(SecurityProfile.level5())
        ek, dk = MLKEM.keygen()
        ss, ct = MLKEM.encaps(ek)
        assert len(ss) == 32
        assert len(ct) == 1568

    def test_dsa_sign_level5_signature_size(self):
        set_security_profile(SecurityProfile.level5())
        vk, sk = MLDSA.keygen()
        sig = MLDSA.sign(sk, b"test message")
        assert len(sig) == 4627

    def test_dsa_verify_level5(self):
        set_security_profile(SecurityProfile.level5())
        vk, sk = MLDSA.keygen()
        msg = b"compliance test"
        sig = MLDSA.sign(sk, msg)
        assert MLDSA.verify(vk, msg, sig) is True
        assert MLDSA.verify(vk, b"wrong message", sig) is False

    def test_keypair_generate_level5(self):
        set_security_profile(SecurityProfile.level5())
        kp = KeyPair.generate("level5-test")
        assert len(kp.ek) == 1568
        assert len(kp.dk) == 3168
        assert len(kp.vk) == 2592
        assert len(kp.sk) == 4896


class TestLevel5SealedBox:
    def test_seal_unseal_level5(self):
        set_security_profile(SecurityProfile.level5())
        kp = KeyPair.generate("seal-test")
        plaintext = b"secret data for Level 5"
        sealed = SealedBox.seal(plaintext, kp.ek)
        recovered = SealedBox.unseal(sealed, kp)
        assert recovered == plaintext

    def test_sealed_size_level5(self):
        set_security_profile(SecurityProfile.level5())
        kp = KeyPair.generate("size-test")
        sealed = SealedBox.seal(b"test", kp.ek)
        # Level 5: ct=1568 + nonce=16 + payload + tag=32
        assert len(sealed) > 1568 + 16 + 32

    def test_wrong_key_fails_level5(self):
        set_security_profile(SecurityProfile.level5())
        alice = KeyPair.generate("alice-l5")
        bob = KeyPair.generate("bob-l5")
        sealed = SealedBox.seal(b"for alice", alice.ek)
        with pytest.raises(ValueError):
            SealedBox.unseal(sealed, bob)


# ===========================================================================
# 2. HASH FUNCTION (§7.1)
# ===========================================================================

class TestHashFunction:
    def test_blake2b_prefix(self):
        h = H(b"test")
        assert h.startswith("blake2b:")

    def test_sha384_prefix(self):
        set_security_profile(SecurityProfile(level=3, hash_fn=HashFunction.SHA_384))
        h = H(b"test")
        assert h.startswith("sha384:")

    def test_sha512_prefix(self):
        set_security_profile(SecurityProfile(level=3, hash_fn=HashFunction.SHA_512))
        h = H(b"test")
        assert h.startswith("sha512:")

    def test_blake2b_bytes_size(self):
        raw = H_bytes(b"test")
        assert len(raw) == 32

    def test_sha384_bytes_size(self):
        set_security_profile(SecurityProfile(level=3, hash_fn=HashFunction.SHA_384))
        raw = H_bytes(b"test")
        assert len(raw) == 48

    def test_sha512_bytes_size(self):
        set_security_profile(SecurityProfile(level=3, hash_fn=HashFunction.SHA_512))
        raw = H_bytes(b"test")
        assert len(raw) == 64

    def test_different_algos_different_hashes(self):
        data = b"comparison test"

        set_security_profile(SecurityProfile(level=3, hash_fn=HashFunction.BLAKE2B_256))
        h_blake = H(data)

        set_security_profile(SecurityProfile(level=3, hash_fn=HashFunction.SHA_384))
        h_sha384 = H(data)

        set_security_profile(SecurityProfile(level=3, hash_fn=HashFunction.SHA_512))
        h_sha512 = H(data)

        assert h_blake != h_sha384
        assert h_sha384 != h_sha512
        assert h_blake != h_sha512

    def test_same_algo_deterministic(self):
        data = b"determinism test"
        h1 = H(data)
        h2 = H(data)
        assert h1 == h2

    def test_aead_works_with_sha384(self):
        set_security_profile(SecurityProfile(level=3, hash_fn=HashFunction.SHA_384))
        key = b"k" * 32
        nonce = b"n" * 16
        plaintext = b"encrypt me with sha384 hash"
        ct = AEAD.encrypt(key, plaintext, nonce)
        pt = AEAD.decrypt(key, ct, nonce)
        assert pt == plaintext

    def test_aead_works_with_sha512(self):
        set_security_profile(SecurityProfile(level=3, hash_fn=HashFunction.SHA_512))
        key = b"k" * 32
        nonce = b"n" * 16
        plaintext = b"encrypt me with sha512 hash"
        ct = AEAD.encrypt(key, plaintext, nonce)
        pt = AEAD.decrypt(key, ct, nonce)
        assert pt == plaintext


class TestHashFunctionEnum:
    def test_blake2b_value(self):
        assert HashFunction.BLAKE2B_256.value == "blake2b"

    def test_sha384_value(self):
        assert HashFunction.SHA_384.value == "sha384"

    def test_sha512_value(self):
        assert HashFunction.SHA_512.value == "sha512"

    def test_all_members(self):
        members = set(HashFunction)
        assert len(members) == 3


# ===========================================================================
# 3. HSM INTERFACE (§7.3)
# ===========================================================================

class TestSoftwareHSMKEM:
    def test_generate_kem_keypair(self):
        hsm = SoftwareHSM()
        ek = hsm.generate_kem_keypair("test-kem-1")
        assert len(ek) == MLKEM.EK_SIZE
        assert hsm.has_key("test-kem-1")

    def test_duplicate_key_id_raises(self):
        hsm = SoftwareHSM()
        hsm.generate_kem_keypair("dup")
        with pytest.raises(ValueError, match="already exists"):
            hsm.generate_kem_keypair("dup")

    def test_kem_decaps(self):
        hsm = SoftwareHSM()
        ek = hsm.generate_kem_keypair("decaps-test")
        # Simulate encapsulation (normally done by sender)
        ss, ct = MLKEM.encaps(ek)
        # Store the encaps mapping in SealedBox (PoC requirement)
        SealedBox._PoC_encaps_table[(H(ek), H(ct))] = ss
        # Decapsulate through HSM
        recovered_ss = hsm.kem_decaps("decaps-test", ct)
        assert recovered_ss == ss

    def test_kem_decaps_wrong_key_fails(self):
        hsm = SoftwareHSM()
        ek1 = hsm.generate_kem_keypair("key-1")
        ek2 = hsm.generate_kem_keypair("key-2")
        ss, ct = MLKEM.encaps(ek1)
        SealedBox._PoC_encaps_table[(H(ek1), H(ct))] = ss
        with pytest.raises(ValueError, match="decapsulation failed"):
            hsm.kem_decaps("key-2", ct)


class TestSoftwareHSMDSA:
    def test_generate_dsa_keypair(self):
        hsm = SoftwareHSM()
        vk = hsm.generate_dsa_keypair("test-dsa-1")
        assert len(vk) == MLDSA.VK_SIZE
        assert hsm.has_key("test-dsa-1")

    def test_sign_through_hsm(self):
        hsm = SoftwareHSM()
        vk = hsm.generate_dsa_keypair("signer")
        msg = b"sign this message"
        sig = hsm.sign("signer", msg)
        assert len(sig) == MLDSA.SIG_SIZE
        # Verify with public key
        assert MLDSA.verify(vk, msg, sig) is True

    def test_sign_wrong_key_type_raises(self):
        hsm = SoftwareHSM()
        hsm.generate_kem_keypair("kem-key")
        with pytest.raises(TypeError, match="not 'dsa'"):
            hsm.sign("kem-key", b"test")

    def test_sign_nonexistent_key_raises(self):
        hsm = SoftwareHSM()
        with pytest.raises(KeyError, match="not found"):
            hsm.sign("no-such-key", b"test")


class TestSoftwareHSMLifecycle:
    def test_destroy_key(self):
        hsm = SoftwareHSM()
        hsm.generate_dsa_keypair("ephemeral")
        assert hsm.has_key("ephemeral")
        assert hsm.destroy_key("ephemeral") is True
        assert hsm.has_key("ephemeral") is False

    def test_destroy_nonexistent_returns_false(self):
        hsm = SoftwareHSM()
        assert hsm.destroy_key("ghost") is False

    def test_list_keys(self):
        hsm = SoftwareHSM()
        hsm.generate_kem_keypair("kem-1")
        hsm.generate_dsa_keypair("dsa-1")
        keys = hsm.list_keys()
        assert len(keys) == 2
        key_ids = {k["key_id"] for k in keys}
        assert key_ids == {"kem-1", "dsa-1"}
        types = {k["type"] for k in keys}
        assert types == {"kem", "dsa"}

    def test_list_keys_empty(self):
        hsm = SoftwareHSM()
        assert hsm.list_keys() == []

    def test_get_public_key(self):
        hsm = SoftwareHSM()
        ek = hsm.generate_kem_keypair("pub-test")
        assert hsm.get_public_key("pub-test") == ek

    def test_get_public_key_nonexistent_raises(self):
        hsm = SoftwareHSM()
        with pytest.raises(KeyError):
            hsm.get_public_key("missing")


class TestSoftwareHSMLevel5:
    def test_kem_keygen_level5(self):
        set_security_profile(SecurityProfile.level5())
        hsm = SoftwareHSM()
        ek = hsm.generate_kem_keypair("l5-kem")
        assert len(ek) == 1568

    def test_dsa_keygen_level5(self):
        set_security_profile(SecurityProfile.level5())
        hsm = SoftwareHSM()
        vk = hsm.generate_dsa_keypair("l5-dsa")
        assert len(vk) == 2592

    def test_sign_verify_level5(self):
        set_security_profile(SecurityProfile.level5())
        hsm = SoftwareHSM()
        vk = hsm.generate_dsa_keypair("l5-signer")
        msg = b"level 5 message"
        sig = hsm.sign("l5-signer", msg)
        assert len(sig) == 4627
        assert MLDSA.verify(vk, msg, sig) is True


# ===========================================================================
# 4. END-TO-END: Full protocol under Level 5 + SHA-384
# ===========================================================================

class TestEndToEndLevel5:
    def test_full_protocol_level5_sha384(self):
        """Complete COMMIT → LATTICE → MATERIALIZE under Level 5 / SHA-384."""
        set_security_profile(SecurityProfile.cnsa2())

        # Setup
        net = CommitmentNetwork()
        for nid, reg in [
            ("n1", "US-East"), ("n2", "US-West"),
            ("n3", "EU-West"), ("n4", "EU-East"),
            ("n5", "AP-East"), ("n6", "AP-South"),
        ]:
            net.add_node(nid, reg)

        protocol = LTPProtocol(net)
        alice = KeyPair.generate("alice-cnsa2")
        bob = KeyPair.generate("bob-cnsa2")

        # Verify key sizes are Level 5
        assert len(alice.ek) == 1568
        assert len(alice.vk) == 2592

        # COMMIT
        entity = Entity(content=b"CNSA 2.0 classified data", shape="x-ltp/test")
        entity_id, record, cek = protocol.commit(entity, alice, n=8, k=4)

        # Verify hash prefix matches profile
        assert entity_id.startswith("sha384:")

        # Verify signature is Level 5 size
        assert len(record.signature) == 4627

        # LATTICE
        sealed = protocol.lattice(entity_id, record, cek, bob)
        # Level 5 sealed size: ct=1568 + nonce=16 + payload + tag
        assert len(sealed) > 1568

        # MATERIALIZE
        content = protocol.materialize(sealed, bob)
        assert content == b"CNSA 2.0 classified data"

    def test_wrong_receiver_level5(self):
        """Unauthorized receiver cannot materialize under Level 5."""
        set_security_profile(SecurityProfile.level5())

        net = CommitmentNetwork()
        for i in range(6):
            net.add_node(f"n{i}", f"R{i}")

        protocol = LTPProtocol(net)
        alice = KeyPair.generate("alice-l5")
        bob = KeyPair.generate("bob-l5")
        eve = KeyPair.generate("eve-l5")

        entity = Entity(content=b"secret", shape="x-ltp/test")
        eid, rec, cek = protocol.commit(entity, alice, n=8, k=4)
        sealed = protocol.lattice(eid, rec, cek, bob)

        # Eve cannot unseal
        result = protocol.materialize(sealed, eve)
        assert result is None


class TestEndToEndWithHSM:
    def test_hsm_sign_verify_roundtrip(self):
        """HSM-generated signatures verify with extracted public key."""
        hsm = SoftwareHSM()
        vk = hsm.generate_dsa_keypair("protocol-signer")
        msg = b"commitment record payload"
        sig = hsm.sign("protocol-signer", msg)
        assert MLDSA.verify(vk, msg, sig) is True

    def test_hsm_multiple_keys(self):
        """HSM manages multiple key pairs simultaneously."""
        hsm = SoftwareHSM()
        vk1 = hsm.generate_dsa_keypair("node-1-dsa")
        vk2 = hsm.generate_dsa_keypair("node-2-dsa")
        ek1 = hsm.generate_kem_keypair("node-1-kem")

        assert len(hsm.list_keys()) == 3

        sig1 = hsm.sign("node-1-dsa", b"msg1")
        sig2 = hsm.sign("node-2-dsa", b"msg2")

        assert MLDSA.verify(vk1, b"msg1", sig1) is True
        assert MLDSA.verify(vk2, b"msg2", sig2) is True
        # Cross-verify should fail
        assert MLDSA.verify(vk1, b"msg2", sig2) is False

    def test_hsm_key_destruction_prevents_signing(self):
        """Destroyed keys cannot be used for operations."""
        hsm = SoftwareHSM()
        hsm.generate_dsa_keypair("destroy-me")
        hsm.destroy_key("destroy-me")
        with pytest.raises(KeyError):
            hsm.sign("destroy-me", b"test")
