"""
in-toto attestation wrapper for provenance receipts.

Emits a receipt as a standard in-toto Statement (v1) so the wider supply-chain
ecosystem (in-toto / SLSA verifiers, policy engines) can consume our provenance
instead of learning a bespoke format. The full ETP receipt is embedded in the
predicate, so the statement stays independently verifiable offline with our
verifier — the outer in-toto envelope is for interop, the inner receipt carries
the cryptographic proof (operator STH signature + inclusion proof + optional
device signature).

    stmt = in_toto_statement("report.pdf", receipt)          # -> dict (JSON)
    receipt2 = receipt_from_statement(stmt)                   # round-trips
    assert receipt2.verify(sealed, expected_operator_vk=vk)

Reference: in-toto Attestation Framework — https://github.com/in-toto/attestation
"""

from __future__ import annotations

from .encoding import b64e
from .provenance import ProvenanceReceipt

__all__ = [
    "IN_TOTO_STATEMENT_TYPE",
    "ETP_PREDICATE_TYPE",
    "in_toto_statement",
    "receipt_from_statement",
]

IN_TOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
ETP_PREDICATE_TYPE = "https://etp-custody.dev/provenance/v1"


def in_toto_statement(subject_name: str, receipt: ProvenanceReceipt) -> dict:
    """
    Wrap a receipt as an in-toto Statement binding `subject_name` to the
    notarized content. The subject digest uses the canonical SHA3-256 content
    hash; the predicate embeds the full receipt for offline verification.
    """
    m = receipt.manifest
    return {
        "_type": IN_TOTO_STATEMENT_TYPE,
        "subject": [{
            "name": subject_name,
            "digest": {"sha3_256": m.content_hash.hex()},
        }],
        "predicateType": ETP_PREDICATE_TYPE,
        "predicate": {
            "capture_id": m.capture_id,
            "originator_id": m.originator_id,
            "captured_at": m.captured_at,
            "device_signed": bool(m.originator_vk),
            "notary_operator_vk": b64e(receipt.sth.operator_vk),
            "attested_root": receipt.sth.root_hash.hex(),
            "sth_sequence": receipt.sth.sequence,
            # Full ETP receipt — makes this statement self-verifying with our tools.
            "receipt": receipt.to_dict(),
        },
    }


def receipt_from_statement(statement: dict) -> ProvenanceReceipt:
    """Recover the embedded ProvenanceReceipt from an in-toto statement."""
    if statement.get("predicateType") != ETP_PREDICATE_TYPE:
        raise ValueError(f"not an ETP provenance statement: {statement.get('predicateType')!r}")
    return ProvenanceReceipt.from_dict(statement["predicate"]["receipt"])
