"""Tests for formal verification model export (Tamarin + ProVerif)."""

import pytest

from src.ltp.verification import (
    VerificationProperty,
    TamarinModel,
    ProVerifModel,
)


# ---------------------------------------------------------------------------
# VerificationProperty enum
# ---------------------------------------------------------------------------

class TestVerificationProperty:
    def test_all_six_properties(self):
        assert len(VerificationProperty) == 6

    def test_whitepaper_refs(self):
        for prop in VerificationProperty:
            ref = prop.whitepaper_ref
            assert "§3.3" in ref
            assert "Theorem" in ref

    def test_machine_checkable_properties(self):
        checkable = [p for p in VerificationProperty if p.machine_checkable]
        assert VerificationProperty.IMM in checkable
        assert VerificationProperty.TCONF in checkable
        assert VerificationProperty.NREP in checkable
        assert VerificationProperty.TIMM in checkable

    def test_non_machine_checkable(self):
        assert not VerificationProperty.SINT.machine_checkable
        assert not VerificationProperty.TSEC.machine_checkable


# ---------------------------------------------------------------------------
# Tamarin Model Export
# ---------------------------------------------------------------------------

class TestTamarinModel:
    def test_exports_valid_theory(self):
        model = TamarinModel.export()
        assert "theory LTP_Protocol" in model
        assert "begin" in model
        assert "end" in model

    def test_includes_builtins(self):
        model = TamarinModel.export()
        assert "builtins:" in model
        assert "hashing" in model
        assert "asymmetric-encryption" in model
        assert "signing" in model

    def test_includes_commit_rule(self):
        model = TamarinModel.export()
        assert "rule Commit:" in model
        assert "Committed(" in model

    def test_includes_lattice_rule(self):
        model = TamarinModel.export()
        assert "rule Lattice:" in model
        assert "Sealed(" in model

    def test_includes_materialize_rule(self):
        model = TamarinModel.export()
        assert "rule Materialize:" in model
        assert "Materialized(" in model

    def test_includes_adversary(self):
        model = TamarinModel.export(include_adversary=True)
        assert "Compromise_LTK" in model
        assert "Compromised(" in model

    def test_excludes_adversary(self):
        model = TamarinModel.export(include_adversary=False)
        assert "Compromise_LTK" not in model

    def test_includes_all_lemmas(self):
        model = TamarinModel.export()
        assert "lemma entity_immutability:" in model
        assert "lemma shard_integrity" in model
        assert "lemma transfer_confidentiality:" in model
        assert "lemma non_repudiation:" in model
        assert "lemma threshold_secrecy" in model
        assert "lemma transfer_immutability:" in model

    def test_specific_properties(self):
        model = TamarinModel.export(
            properties=[VerificationProperty.IMM, VerificationProperty.TCONF],
        )
        assert "entity_immutability" in model
        assert "transfer_confidentiality" in model
        assert "non_repudiation" not in model

    def test_keygen_rules(self):
        model = TamarinModel.export()
        assert "Generate_KeyPair" in model
        assert "Generate_Signing_Key" in model

    def test_equality_restriction(self):
        model = TamarinModel.export()
        assert "restriction Equality:" in model


# ---------------------------------------------------------------------------
# ProVerif Model Export
# ---------------------------------------------------------------------------

class TestProVerifModel:
    def test_exports_valid_model(self):
        model = ProVerifModel.export()
        assert "ProVerif Model" in model
        assert "type skey." in model
        assert "type pkey." in model
        assert "process" in model

    def test_includes_crypto_primitives(self):
        model = ProVerifModel.export()
        assert "fun pk(skey): pkey." in model
        assert "fun aenc(" in model
        assert "fun sign(" in model
        assert "fun senc(" in model
        assert "fun hash(" in model

    def test_includes_sender_process(self):
        model = ProVerifModel.export()
        assert "let Sender(" in model
        assert "event Committed(" in model
        assert "event Sealed(" in model

    def test_includes_receiver_process(self):
        model = ProVerifModel.export()
        assert "let Receiver(" in model
        assert "event Materialized(" in model

    def test_includes_secrecy_query(self):
        model = ProVerifModel.export()
        assert "attacker(secret_content)" in model

    def test_includes_authentication_query(self):
        model = ProVerifModel.export()
        assert "event(Materialized(" in model

    def test_specific_properties(self):
        model = ProVerifModel.export(
            properties=[VerificationProperty.TCONF],
        )
        assert "attacker(secret_content)" in model

    def test_main_process(self):
        model = ProVerifModel.export()
        assert "new sender_sigk: sigkey;" in model
        assert "new receiver_sk: skey;" in model
        assert "Sender(sender_sigk, receiver_pk)" in model
        assert "Receiver(receiver_sk, sender_vk)" in model
