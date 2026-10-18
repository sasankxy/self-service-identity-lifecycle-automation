import pytest

from nlu.pipeline import NLUPipeline
from nlu.schemas import ModelNotTrainedError


def types(r, blocking=None):
    return {a["type"] for a in r["ambiguities"] if blocking is None or a["blocking"] == blocking}


def test_unknown_intent_asks_for_clarification(pipe):
    r = pipe.parse("Hello")
    assert r["status"] == "UNKNOWN_INTENT" and "unknown_intent" in types(r) and r["clarification_questions"]


def test_unsupported_request(pipe):
    r = pipe.parse("Reset my password.")
    assert r["status"] == "UNKNOWN_INTENT" and "unsupported_request" in types(r)


def test_pronoun_without_referent(pipe):
    r = pipe.parse("Move him to Finance.")
    assert "unresolved_pronoun" in types(r, True) and "person" in r["missing_fields"]
    assert any("pronoun" in q.lower() for q in r["clarification_questions"])
    assert r["slots"]["person"] is None


def test_multiple_people_are_not_collapsed(pipe):
    r = pipe.parse("Revoke access for Rahul Sharma and Priya Nair on SAP.")
    assert "multiple_persons" in types(r, True) and r["slots"]["person"] is None
    assert r["status"] == "NEEDS_CLARIFICATION"


def test_conflicting_intents_flagged(pipe):
    r = pipe.parse("Offboard Rahul Sharma and revoke his SAP access.")
    assert "multiple_intents" in types(r, True) and r["status"] == "NEEDS_CLARIFICATION"
    assert len(r["intent"]["candidates"]) >= 2


def test_partial_name_is_informational_not_blocking(pipe):
    r = pipe.parse("Revoke Ananya's Salesforce access at the end of the month.")
    assert "partial_name" in types(r, False)
    assert not types(r, True) and r["status"] == "PARSED"


def test_unresolved_vague_date_is_informational(pipe):
    r = pipe.parse("Onboard Meera Krishnan into Marketing next week.")
    assert "unresolved_date" in types(r, False) and r["status"] == "PARSED"


def test_confidence_types_are_distinguished(pipe):
    r = pipe.parse("Revoke Ananya's Salesforce access at the end of the month.")
    assert r["intent"]["confidence_type"] == "heuristic"
    crf = [e for e in r["entities"] if e["method"] == "crf"][0]
    assert crf["confidence_type"] == "crf_marginal_mean"
    assert all(e["confidence"] is None for e in r["entities"] if e["method"] == "rule_based")


def test_empty_and_invalid_input(pipe):
    assert pipe.parse("   ")["status"] == "UNKNOWN_INTENT"
    with pytest.raises(TypeError):
        pipe.parse(None)


def test_statistical_modes_fail_loudly_without_models(tmp_path):
    with pytest.raises(ModelNotTrainedError):
        NLUPipeline(models_dir=tmp_path)  # default modes need trained models; no silent fallback
    p = NLUPipeline(models_dir=tmp_path, ner_mode="rules_only", intent_mode="rules_only")
    assert p.parse("Revoke my Jira access")["meta"]["ner_mode"] == "rules_only"
