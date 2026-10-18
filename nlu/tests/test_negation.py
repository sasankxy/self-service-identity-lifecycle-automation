import pytest


@pytest.mark.parametrize("text,negated", [
    ("Do not revoke my access", "ACCESS_REVOCATION"),
    ("Please don't remove access to SAP for Priya Nair", "ACCESS_REVOCATION"),
    ("Never grant Priya Nair admin access to Jira", "ACCESS_REQUEST"),
    ("Priya Nair is not leaving the company", "LEAVER"),
    ("Do not move Priya Nair to Finance", "MOVER"),
    ("We are not onboarding Priya Nair tomorrow", "JOINER"),
    ("No need to revoke my access to SAP", "ACCESS_REVOCATION"),
])
def test_negated_actions_do_not_trigger_the_intent(pipe, text, negated):
    r = pipe.parse(text)
    assert r["intent"]["label"] == "UNKNOWN" and r["status"] == "UNKNOWN_INTENT"
    assert negated in r["intent"]["negated_candidates"]
    assert any(a["type"] == "negated_action" and a["blocking"] for a in r["ambiguities"])
    assert r["clarification_questions"]
    assert r["slots"] == {}


def test_action_entity_carries_negation_flag(pipe):
    acts = [e for e in pipe.parse("Do not revoke my access")["entities"] if e["type"] == "ACTION"]
    assert acts and acts[0]["negated"] is True
    acts = [e for e in pipe.parse("Revoke my access")["entities"] if e["type"] == "ACTION"]
    assert acts and acts[0]["negated"] is False


def test_negation_does_not_leak_across_clause_break(pipe):
    r = pipe.parse("Don't move Priya Nair to Finance; revoke her Jira access instead.")
    assert r["intent"]["label"] == "ACCESS_REVOCATION"
    assert any(a["type"] == "mixed_negation" for a in r["ambiguities"]) and r["status"] == "NEEDS_CLARIFICATION"


def test_no_longer_need_is_a_revocation_not_a_request(pipe):
    assert pipe.parse("I no longer need access to Jira")["intent"]["label"] == "ACCESS_REVOCATION"


def test_nb_alone_is_not_trusted_for_negation(pipe):
    from nlu.pipeline import NLUPipeline
    hyb = pipe.parse("Do not revoke my access to SAP")
    assert hyb["intent"]["label"] == "UNKNOWN" and hyb["intent"]["method"] == "rule_based"
