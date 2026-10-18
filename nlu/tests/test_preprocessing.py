from nlu.config_loader import load_configs
from nlu.preprocessing import negated_at, preprocess, tokenize

_, PAT = load_configs()


def test_offsets_roundtrip():
    text = "Revoke Ananya's Salesforce access, at the end of the month."
    for t in tokenize(text):
        assert text[t.start:t.end] == t.text


def test_possessive_is_split():
    toks = [t.text for t in tokenize("Ananya's access")]
    assert toks == ["Ananya", "'s", "access"]


def test_hyphen_ids_and_dates_stay_single_tokens():
    toks = [t.text for t in tokenize("EMP-7712 on 30/11/2026 and 2026-11-30 read-only")]
    assert toks == ["EMP-7712", "on", "30/11/2026", "and", "2026-11-30", "read-only"]


def test_typo_correction_only_sets_corr_never_changes_offsets():
    doc = preprocess("Revke Rahul's acess", PAT["typo_lexicon"])
    assert doc.tokens[0].corr == "revoke" and doc.tokens[0].text == "Revke"
    assert doc.text[doc.tokens[-1].start:doc.tokens[-1].end] == "acess"


def test_valid_inflections_are_not_corrected():
    doc = preprocess("Access was revoked and requests granted", PAT["typo_lexicon"])
    assert all(t.corr is None for t in doc.tokens)


def test_names_are_not_typo_corrected():
    doc = preprocess("Please give Reevoke access", PAT["typo_lexicon"])
    assert doc.tokens[2].corr is None


def test_negation_window_and_clause_break():
    doc = preprocess("Do not revoke access, revoke it", PAT["typo_lexicon"])
    neg, br = set(PAT["negators"]), set(PAT["clause_break_words"])
    assert negated_at(doc.tokens, 2, neg, br, 3) is True
    assert negated_at(doc.tokens, 5, neg, br, 3) is False


def test_empty_text():
    assert preprocess("").tokens == []
