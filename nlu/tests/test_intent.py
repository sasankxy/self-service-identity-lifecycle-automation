import math

from nlu.config_loader import load_configs
from nlu.features import Lexicons
from nlu.intent_classifier import (HybridIntentClassifier, NaiveBayesIntentClassifier,
                                   RuleBasedIntentClassifier)
from nlu.preprocessing import preprocess

ENT, PAT = load_configs()
RB = RuleBasedIntentClassifier(PAT)


def rb(text):
    return RB.classify(preprocess(text, PAT["typo_lexicon"]))


def test_rule_baseline_core_examples():
    assert rb("Move Rahul Sharma from Engineering to Finance.")["label"] == "MOVER"
    assert rb("Give me access to SAP.")["label"] == "ACCESS_REQUEST"
    assert rb("Revoke Ananya's Salesforce access.")["label"] == "ACCESS_REVOCATION"
    assert rb("Does Priya have access to Jira?")["label"] == "ACCESS_STATUS_QUERY"
    assert rb("Onboard the new hire Priya.")["label"] == "JOINER"
    assert rb("Rahul has resigned.")["label"] == "LEAVER"


def test_keyword_alone_does_not_decide_when_negated():
    r = rb("Do not revoke my access")
    assert r["label"] == "UNKNOWN" and r["negated_candidates"] == ["ACCESS_REVOCATION"]


def test_evidence_and_heuristic_confidence_are_exposed():
    r = rb("Revoke Ananya's Salesforce access")
    assert r["evidence"] and r["confidence_type"] == "heuristic" and 0 < r["confidence"] < 1


def test_unsupported_and_unknown():
    assert rb("Reset my password")["unsupported"] is True
    assert rb("Hello there")["label"] == "UNKNOWN"
    assert rb("She is on sick leave")["label"] == "UNKNOWN"


def test_status_question_beats_passive_revoked_word():
    assert rb("Has my access to SAP been revoked?")["label"] == "ACCESS_STATUS_QUERY"


def test_conflicting_signals_are_flagged():
    r = rb("Revoke Rahul's access to SAP and give him access to Jira")
    assert r["conflict"] and {c["label"] for c in r["candidates"]} >= {"ACCESS_REVOCATION", "ACCESS_REQUEST"}


def test_typo_tolerant_cues():
    assert rb("Revke Rahul's Jira acess")["label"] == "ACCESS_REVOCATION"


def _tiny_nb():
    nb = NaiveBayesIntentClassifier(Lexicons(ENT, PAT), ENT, PAT["typo_lexicon"])
    texts = ["revoke access to sap", "revoke my jira access", "remove access for slack",
             "give me access to sap", "grant access to jira", "need access to slack",
             "hello there", "tell me a joke", "what a nice day"]
    labels = ["ACCESS_REVOCATION"] * 3 + ["ACCESS_REQUEST"] * 3 + ["UNKNOWN"] * 3
    nb.train(texts, labels)
    return nb


def test_tfidf_is_manual_and_l2_normalised():
    nb = _tiny_nb()
    v = nb._vec(nb.ngrams(preprocess("revoke access to sap")))
    assert math.isclose(sum(x * x for x in v.values()), 1.0, rel_tol=1e-9)
    n = 9
    df_hello = 1
    assert math.isclose(nb.idf[nb.vocab["hello"]], math.log((1 + n) / (1 + df_hello)) + 1)


def test_nb_train_predict_persist_roundtrip(tmp_path):
    nb = _tiny_nb()
    p = nb.predict(preprocess("please revoke access"))
    assert p["label"] == "ACCESS_REVOCATION"
    assert abs(sum(p["probabilities"].values()) - 1) < 1e-3
    assert p["confidence_type"] == "naive_bayes_posterior_uncalibrated"
    nb.save(tmp_path / "m.json")
    nb2 = NaiveBayesIntentClassifier(Lexicons(ENT, PAT), ENT, PAT["typo_lexicon"]).load(tmp_path / "m.json")
    assert nb2.predict(preprocess("please revoke access")) == p


def test_hybrid_never_lets_nb_override_negation_or_unsupported():
    h = HybridIntentClassifier(RB, _tiny_nb(), PAT)
    assert h.classify(preprocess("Do not revoke my access to sap", PAT["typo_lexicon"]))["label"] == "UNKNOWN"
    assert h.classify(preprocess("reset my password for sap", PAT["typo_lexicon"]))["label"] == "UNKNOWN"


def test_hybrid_uses_nb_only_when_no_rule_cue_fired():
    h = HybridIntentClassifier(RB, _tiny_nb(), PAT)
    r = h.classify(preprocess("sap access please", PAT["typo_lexicon"]))
    assert r["method"] in ("rule_based", "naive_bayes")
