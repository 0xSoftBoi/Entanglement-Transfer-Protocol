"""
Witness cosigning — an independent party countersigns tree heads.

The anti-split-view defense: the operator alone can show different log views to
different parties (equivocation is detectable after the fact via `audit`, but
only if victims compare notes). A witness — a second, independently-operated
keypair — countersigns each STH it observes; a relying party who requires
"operator + witness" signatures on a tree head knows that at least one honest
witness saw the same view they did.

Cosignatures are domain-tagged (DOMAIN_WITNESS_COSIGN) over the STH's
(sequence, tree_size, root, operator_vk) so a cosignature can never be replayed
onto another operator's log or another tree state.

    witness = Witness(witness_keypair)
    cosig = witness.cosign(sth)
    assert cosig.verify(sth)

The service exposes cosignatures alongside /v1/sth when configured with a
witness; production runs witnesses as separate parties on separate infra.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..keypair import KeyPair
from ..primitives import MLDSA
from ..encoding import CanonicalEncoder, b64e, b64d
from ..domain import DOMAIN_WITNESS_COSIGN
from ..merkle_log import SignedTreeHead

__all__ = ["Witness", "Cosignature"]


def _payload(sth: SignedTreeHead) -> bytes:
    return (
        CanonicalEncoder(DOMAIN_WITNESS_COSIGN)
        .uint64(sth.sequence)
        .uint64(sth.tree_size)
        .raw_bytes(sth.root_hash)
        .length_prefixed_bytes(sth.operator_vk)
        .finalize()
    )


@dataclass(frozen=True)
class Cosignature:
    witness_vk: bytes
    signature: bytes

    def verify(self, sth: SignedTreeHead) -> bool:
        """True iff this witness really countersigned exactly this tree state."""
        return MLDSA.verify(self.witness_vk, _payload(sth), self.signature)

    def to_dict(self) -> dict:
        return {"witness_vk": b64e(self.witness_vk), "signature": b64e(self.signature)}

    @classmethod
    def from_dict(cls, d: dict) -> "Cosignature":
        return cls(witness_vk=b64d(d["witness_vk"]), signature=b64d(d["signature"]))


class Witness:
    def __init__(self, keypair: KeyPair) -> None:
        self._kp = keypair

    @property
    def vk(self) -> bytes:
        return self._kp.vk

    def cosign(self, sth: SignedTreeHead) -> Cosignature:
        """
        Countersign an STH the witness has verified for itself. A production
        witness MUST check sth.verify() and append-only consistency against
        the previous STH it cosigned before signing — enforced here for the
        signature check (consistency requires the witness's own state).
        """
        if not sth.verify():
            raise ValueError("refusing to cosign an STH with an invalid operator signature")
        return Cosignature(
            witness_vk=self._kp.vk,
            signature=MLDSA.sign(self._kp.sk, _payload(sth)),
        )
