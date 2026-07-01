"""
Operator key custody — pluggable STH signers (E1).

The reference deployment stores the operator KeyPair in the service database
(`store.get_or_create_operator()`). That is fine for development and useless
against the threat the operator key actually faces: anyone who reads the DB
(backup leak, SQL access, subpoenaed disk) can sign tree heads and rewrite
history convincingly. Production custody moves the signing key into a KMS/HSM
where it can be *used* but never *read*.

This module is the seam:

    Signer            — duck-typed interface: `.vk` (bytes) + `.sign(payload)`
    LocalSigner       — wraps a KeyPair (the reference behavior, unchanged)
    KMSSigner         — AWS KMS asymmetric key, KeySpec ML_DSA_65 (KMS has
                        supported FIPS-204 ML-DSA key types since 2025); the
                        private key is generated inside KMS and is not
                        exportable
    signer_from_env   — ETP_CLOUD_KMS_KEY_ID set → KMSSigner, else the
                        store-persisted LocalSigner

`ProvenanceLog`, `MerkleLog`, and `Witness` all accept any Signer, so the
whole service (STH publication, witness cosigning, receipt verification)
works identically over either custody mode — verification only ever needs
the public vk.

The chain-anchoring EOA key (secp256k1) is the other half of E1; its KMS
path lives behind `AnchorClient` and needs a funded account to verify, so it
stays design-documented until then (see CUSTODY_CLOUD_DESIGN.md §11).
"""

from __future__ import annotations

import os

from ..keypair import KeyPair
from ..primitives import MLDSA

__all__ = ["LocalSigner", "KMSSigner", "signer_from_env"]

# ML-DSA-65 (FIPS 204) verification keys are exactly this long; used to
# validate what we extract from the KMS-returned SubjectPublicKeyInfo.
_MLDSA65_VK_SIZE = 1952


class LocalSigner:
    """Reference custody: an in-process KeyPair (dev/test, or self-hosters
    who accept DB-resident keys). Signing semantics are byte-identical to
    passing the KeyPair around directly."""

    def __init__(self, keypair: KeyPair) -> None:
        self._kp = keypair

    @property
    def vk(self) -> bytes:
        return self._kp.vk

    def sign(self, payload: bytes) -> bytes:
        return MLDSA.sign(self._kp.sk, payload)

    def describe(self) -> str:
        return f"local keypair '{self._kp.label}'"


def _der_spki_raw_key(der: bytes) -> bytes:
    """Extract the raw public key from a DER SubjectPublicKeyInfo.

    SPKI is SEQUENCE { AlgorithmIdentifier, BIT STRING }; the raw key is the
    BIT STRING contents after its unused-bits octet. A minimal TLV walk is
    enough — we validate the result by length and, at sign time, by an
    actual verify, so a malformed blob cannot slip through silently.
    """
    def read_tlv(buf: bytes, off: int) -> tuple[int, bytes, int]:
        if off + 2 > len(buf):
            raise ValueError("truncated DER")
        tag = buf[off]
        length = buf[off + 1]
        off += 2
        if length & 0x80:  # long form
            n = length & 0x7F
            if n == 0 or off + n > len(buf):
                raise ValueError("bad DER length")
            length = int.from_bytes(buf[off:off + n], "big")
            off += n
        if off + length > len(buf):
            raise ValueError("truncated DER value")
        return tag, buf[off:off + length], off + length

    tag, body, _ = read_tlv(der, 0)
    if tag != 0x30:
        raise ValueError("SPKI: expected outer SEQUENCE")
    # AlgorithmIdentifier (skipped), then the subjectPublicKey BIT STRING.
    tag, _alg, off = read_tlv(body, 0)
    if tag != 0x30:
        raise ValueError("SPKI: expected AlgorithmIdentifier SEQUENCE")
    tag, bitstr, _ = read_tlv(body, off)
    if tag != 0x03 or not bitstr or bitstr[0] != 0:
        raise ValueError("SPKI: expected BIT STRING with 0 unused bits")
    return bitstr[1:]


class KMSSigner:
    """AWS KMS custody for the operator's ML-DSA-65 signing key.

    The key is created in KMS (KeySpec=ML_DSA_65, KeyUsage=SIGN_VERIFY) and
    never leaves it; this class fetches the public vk once and delegates each
    STH signature to `kms:Sign`. Every returned signature is verified locally
    before use, so a misconfigured key spec or algorithm fails at the first
    signature instead of producing receipts nobody can verify.

    Pass `client` explicitly for testing; otherwise boto3 builds one from the
    ambient AWS credentials (imported lazily so the [cloud] stack does not
    require boto3 unless KMS custody is actually configured).
    """

    SIGNING_ALGORITHM = "ML_DSA_SHAKE_256"

    def __init__(self, key_id: str, client=None) -> None:
        if client is None:
            import boto3  # lazy: only KMS deployments need it
            client = boto3.client("kms")
        self._kms = client
        self._key_id = key_id
        spki = client.get_public_key(KeyId=key_id)["PublicKey"]
        vk = _der_spki_raw_key(spki)
        if len(vk) != _MLDSA65_VK_SIZE:
            raise ValueError(
                f"KMS key {key_id} is not ML-DSA-65: public key is "
                f"{len(vk)} bytes, expected {_MLDSA65_VK_SIZE} "
                "(create it with KeySpec=ML_DSA_65, KeyUsage=SIGN_VERIFY)")
        self._vk = vk

    @property
    def vk(self) -> bytes:
        return self._vk

    def sign(self, payload: bytes) -> bytes:
        sig = self._kms.sign(
            KeyId=self._key_id,
            Message=payload,
            MessageType="RAW",
            SigningAlgorithm=self.SIGNING_ALGORITHM,
        )["Signature"]
        # Fail-fast: a signature our own verifiers reject must never be
        # published on an STH.
        if not MLDSA.verify(self._vk, payload, sig):
            raise RuntimeError(
                f"KMS key {self._key_id} produced a signature that does not "
                "verify against its own public key — key spec/algorithm "
                "mismatch, refusing to publish")
        return sig

    def describe(self) -> str:
        return f"AWS KMS key {self._key_id}"


def signer_from_env(store, *, kms_client=None):
    """Resolve operator custody from the environment.

    ETP_CLOUD_KMS_KEY_ID set → KMSSigner on that key (the DB never holds a
    signing key). Unset → the reference store-persisted keypair, unchanged.
    """
    key_id = os.environ.get("ETP_CLOUD_KMS_KEY_ID")
    if key_id:
        return KMSSigner(key_id, client=kms_client)
    return LocalSigner(store.get_or_create_operator())
