import json

import pytest

from nlu.config_loader import DEFAULT_DATA_DIR, load_configs
from nlu.ner import CRFNER, HybridNER, RuleBasedNER, bio_to_spans, spans_to_bio
from nlu.features import Lexicons
from nlu.preprocessing import preprocess
from nlu.schemas import MissingDependencyError, ModelNotTrainedError

ENT, PAT = load_configs()
RULES = RuleBasedNER(ENT, PAT)


def rule_ents(text):
    doc = preprocess(text, PAT["typo_lexicon"])
    es, conflicts = HybridNER(RULES, None, "rules_only").extract(doc)
    return {(e.text, e.type): e for e in es}, conflicts


def test_gold_spans_align_with_tokens_and_bio_roundtrips():
    for fname in ("ner_train.json", "ner_test.json"):
        for ex in json.loads((DEFAULT_DATA_DIR / fname).read_text()):
            doc = preprocess(ex["text"])
            tags = spans_to_bio(doc, ex["entities"])
            assert tags == ex["bio"]
            back = {(s, e, t) for s, e, t, _, _ in bio_to_spans(doc, tags)}
            assert back == {(x["start"], x["end"], x["type"]) for x in ex["entities"]}


def test_longest_match_wins_over_shorter_overlap():
    ents, conflicts = rule_ents("Give me access to Sales Force")
    assert ("Sales Force", "APPLICATION") in ents and ("Sales", "DEPARTMENT") not in ents
    assert any(c["discarded"].text == "Sales" for c in conflicts)


def test_role_beats_department_substring():
    ents, _ = rule_ents("Make her a Finance Approver")
    assert ents[("Finance Approver", "ACCESS_ROLE")].normalized == "Finance Approver"
    assert ("Finance", "DEPARTMENT") not in ents


def test_case_sensitive_alias_it_vs_pronoun():
    assert ("IT", "DEPARTMENT") in rule_ents("Move Raj to IT")[0]
    assert not any(t == "DEPARTMENT" for _, t in rule_ents("I need it tomorrow")[0])


def test_alias_and_fuzzy_match_are_labelled():
    ents, _ = rule_ents("Revoke SFDC and Githb access")
    assert ents[("SFDC", "APPLICATION")].normalized == "Salesforce"
    fz = ents[("Githb", "APPLICATION")]
    assert fz.normalized == "GitHub" and fz.match == "fuzzy" and fz.method == "rule_based_fuzzy"


def test_dates_are_extracted_as_spans_only():
    ents, _ = rule_ents("Move Raj tomorrow, then at the end of the month, or next Monday")
    dates = {t for t, ty in ents if ty == "EFFECTIVE_DATE"}
    assert dates == {"tomorrow", "at the end of the month", "next Monday"}


def test_reason_is_cut_before_a_date_and_at_punctuation():
    ents, _ = rule_ents("Move Raj to Finance because of a restructure tomorrow, thanks.")
    assert ("because of a restructure", "REASON") in ents


def test_employee_id_variants():
    for text, expected in [("Offboard EMP4821", "EMP4821"), ("Offboard E-10293", "E-10293"),
                           ("Offboard employee ID 55821", "55821")]:
        assert (expected, "EMPLOYEE_IDENTIFIER") in rule_ents(text)[0]


def test_leave_of_absence_is_not_an_action():
    assert not any(t == "ACTION" for _, t in rule_ents("She is on annual leave")[0])


def test_crf_model_predicts_person_with_confidence(pipe):
    r = pipe.parse("Move Rahul Sharma from Engineering to Finance.")
    p = [e for e in r["entities"] if e["type"] == "PERSON"][0]
    assert (p["text"], p["start"], p["end"], p["method"]) == ("Rahul Sharma", 5, 17, "crf")
    assert 0 < p["confidence"] <= 1 and p["confidence_type"] == "crf_marginal_mean"


def test_rules_override_crf_on_overlap(pipe):
    r = pipe.parse("Give Priya Nair admin access to Sales Force")
    types = {e["text"]: e["type"] for e in r["entities"]}
    assert types["Sales Force"] == "APPLICATION" and types["admin"] == "ACCESS_ROLE"


def test_crf_pronoun_is_never_accepted_as_date_or_person(pipe):
    r = pipe.parse("Aisha starts in Finance next Wednesday, please onboard them.")
    assert not any(e["text"] == "them" for e in r["entities"])


def test_entity_offsets_match_input_text(pipe):
    for text in ["Move Rahul Sharma from Engineering to Finance.", "  Give me access to SAP  ",
                 "Revoke Ananya's Salesforce access at the end of the month."]:
        for e in pipe.parse(text)["entities"]:
            assert text[e["start"]:e["end"]] == e["text"]


def test_missing_crf_model_reports_clearly(tmp_path):
    with pytest.raises(ModelNotTrainedError):
        CRFNER(Lexicons(ENT, PAT)).load(tmp_path / "nope.crfsuite")


def test_missing_dependency_is_reported_not_swallowed(monkeypatch):
    import builtins
    real = builtins.__import__

    def fake(name, *a, **k):
        if name.startswith("sklearn_crfsuite"):
            raise ImportError("simulated")
        return real(name, *a, **k)
    monkeypatch.setattr(builtins, "__import__", fake)
    with pytest.raises(MissingDependencyError, match="sklearn-crfsuite"):
        CRFNER(Lexicons(ENT, PAT))
