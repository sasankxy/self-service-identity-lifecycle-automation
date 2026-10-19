"""Hybrid custom NER: rule-based phrase/pattern matcher + CRF sequence labeller.

Conflict-resolution strategy (see README "NER conflict resolution"):
  1. Rule candidates are ranked by token length (longest first), then type priority
     (EMPLOYEE_IDENTIFIER > EFFECTIVE_DATE > ACCESS_ROLE > APPLICATION > DEPARTMENT > ACTION > REASON),
     then exact-before-fuzzy, then position. Greedy non-overlapping selection.
  2. CRF entities are kept only if they do not overlap a selected rule entity. Rules win on overlap
     because dictionaries/patterns are curated and deterministic; the CRF fills in everything else
     (PERSON, unknown departments/applications, unusual dates, ...).
  3. Every discarded candidate is recorded as a conflict so the ambiguity stage can report it.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from .entity_normalizer import DictionaryIndex
from .features import Lexicons, doc_to_features
from .preprocessing import Doc, preprocess
from .schemas import ENTITY_TYPES, Entity, MissingDependencyError, ModelNotTrainedError

PRIORITY = {"EMPLOYEE_IDENTIFIER": 0, "EFFECTIVE_DATE": 1, "ACCESS_ROLE": 2, "APPLICATION": 3,
            "DEPARTMENT": 4, "ACTION": 5, "REASON": 6, "PERSON": 7}


def _ent(doc: Doc, s: int, e: int, etype: str, method="rule_based", normalized=None, match=None) -> Entity:
    return Entity(text=doc.text[s:e], type=etype, start=s, end=e, method=method,
                  normalized=normalized, match=match)


# ============================================================================ rules
class RuleBasedNER:
    def __init__(self, entities_cfg: dict, patterns_cfg: dict, index: Optional[DictionaryIndex] = None):
        self.index = index or DictionaryIndex(entities_cfg, patterns_cfg)
        self.cfg = patterns_cfg
        self._by_first: Dict[str, list] = {}
        for e in self.index.entries:
            key = e.raw_tokens[0] if e.case_sensitive else e.tokens[0]
            self._by_first.setdefault(key, []).append(e)
        self._act_by_first: Dict[str, list] = {}
        for phrase in self.index.actions:
            self._act_by_first.setdefault(phrase[0], []).append(phrase)
        self.date_res = [(p["name"], re.compile(p["regex"], re.I)) for p in patterns_cfg["temporal_patterns"]]
        self.id_res = [(re.compile(p["regex"], re.I), p["group"]) for p in patterns_cfg["employee_id_patterns"]]
        self.reason_re = re.compile(patterns_cfg["reason_regex"], re.I)
        self.block_res = [re.compile(p, re.I) for p in patterns_cfg["action_context_blocklist"]]

    # ---- individual extractors
    def _dictionary(self, doc: Doc) -> List[Entity]:
        out, toks = [], doc.tokens
        for i, tok in enumerate(toks):
            for key in (tok.text, tok.norm):
                for e in self._by_first.get(key, []):
                    n = len(e.tokens)
                    if i + n > len(toks):
                        continue
                    seg = toks[i:i + n]
                    ok = (all(t.text == r for t, r in zip(seg, e.raw_tokens)) if e.case_sensitive
                          else all(t.norm == r for t, r in zip(seg, e.tokens)))
                    if ok and (e.case_sensitive or key == tok.norm):
                        out.append(_ent(doc, seg[0].start, seg[-1].end, e.etype,
                                        normalized=e.canonical, match="exact"))
        seen, uniq = set(), []
        for c in out:
            k = (c.start, c.end, c.type)
            if k not in seen:
                seen.add(k)
                uniq.append(c)
        return uniq

    def _fuzzy(self, doc: Doc, exact: List[Entity]) -> List[Entity]:
        covered = {i for c in exact for i in range(*doc.span_to_tokens(c.start, c.end))}
        out = []
        for tok in doc.tokens:
            if tok.index in covered or tok.corr or not tok.text[0].isalpha():
                continue
            fz = self.index.fuzzy_lookup(None, tok.text)
            if fz:
                c = _ent(doc, tok.start, tok.end, fz[1], method="rule_based_fuzzy",
                         normalized=fz[0], match="fuzzy")
                c.confidence, c.confidence_type = round(fz[2], 3), "heuristic"
                out.append(c)
        return out

    def _ids(self, doc: Doc) -> List[Entity]:
        out = []
        for rx, g in self.id_res:
            for m in rx.finditer(doc.text):
                out.append(_ent(doc, m.start(g), m.end(g), "EMPLOYEE_IDENTIFIER"))
        return out

    def _dates(self, doc: Doc) -> List[Entity]:
        return [_ent(doc, m.start(), m.end(), "EFFECTIVE_DATE")
                for _, rx in self.date_res for m in rx.finditer(doc.text)]

    def _actions(self, doc: Doc) -> List[Entity]:
        blocked = set()
        for rx in self.block_res:
            for m in rx.finditer(doc.clean):
                a = doc.clean_pos_to_token(m.start())
                b = doc.clean_pos_to_token(max(m.start(), m.end() - 1))
                blocked.update(range(a, b + 1))
        out, toks = [], doc.tokens
        for i, tok in enumerate(toks):
            for phrase in self._act_by_first.get(tok.match, []):
                n = len(phrase)
                seg = toks[i:i + n]
                if len(seg) == n and all(t.match == p for t, p in zip(seg, phrase)):
                    if any(t.index in blocked for t in seg):
                        continue
                    fuzzy = any(t.corr for t in seg)
                    out.append(_ent(doc, seg[0].start, seg[-1].end, "ACTION",
                                    method="rule_based_fuzzy" if fuzzy else "rule_based",
                                    normalized=self.index.actions[phrase]))
        return out

    def _reasons(self, doc: Doc, dates: List[Entity]) -> List[Entity]:
        out = []
        for m in self.reason_re.finditer(doc.text):
            s, e = m.start(), m.end()
            cuts = [d.start for d in dates if s < d.start < e]
            if cuts:
                e = min(cuts)
            text = doc.text[s:e].rstrip()
            e = s + len(text)
            if len(text.split()) >= 2:
                out.append(_ent(doc, s, e, "REASON"))
        return out

    def extract(self, doc: Doc) -> List[Entity]:
        exact = self._dictionary(doc)
        dates = self._dates(doc)
        return (exact + self._fuzzy(doc, exact) + self._ids(doc) + dates
                + self._actions(doc) + self._reasons(doc, dates))


# ============================================================================ CRF
def spans_to_bio(doc: Doc, spans: Sequence[dict]) -> List[str]:
    tags = ["O"] * len(doc.tokens)
    for sp in spans:
        i, j = doc.span_to_tokens(sp["start"], sp["end"])
        covered = doc.tokens[i:j]
        if not covered or covered[0].start != sp["start"] or covered[-1].end != sp["end"]:
            raise ValueError(f"span {sp} does not align with token boundaries in {doc.text!r}")
        for k in range(i, j):
            tags[k] = ("B-" if k == i else "I-") + sp["type"]
    return tags


def bio_to_spans(doc: Doc, tags: Sequence[str]) -> List[Tuple[int, int, str, int, int]]:
    """-> list of (char_start, char_end, type, tok_start, tok_end). Tolerates I- without B-."""
    spans, cur = [], None
    for i, tag in enumerate(list(tags) + ["O"]):
        if tag == "O" or tag.startswith("B-") or (cur and tag[2:] != cur[0]):
            if cur:
                spans.append((doc.tokens[cur[1]].start, doc.tokens[i - 1].end, cur[0], cur[1], i))
                cur = None
        if tag != "O" and cur is None:
            cur = (tag[2:], i)
    return spans


class CRFNER:
    """Linear-chain CRF (sklearn-crfsuite) with our own features and BIO tagging."""

    def __init__(self, lexicons: Lexicons, typo_lexicon: Sequence[str] = ()):
        try:
            import sklearn_crfsuite  # noqa: F401
        except ImportError as exc:
            raise MissingDependencyError(
                "sklearn-crfsuite is required for the statistical NER (pip install sklearn-crfsuite). "
                "No alternative algorithm is substituted automatically.") from exc
        self.lex = lexicons
        self.typo_lexicon = list(typo_lexicon)
        self.crf = None

    def _docs_xy(self, examples):
        X, y = [], []
        for ex in examples:
            doc = preprocess(ex["text"], self.typo_lexicon)
            X.append(doc_to_features(doc, self.lex))
            y.append(spans_to_bio(doc, ex["entities"]))
        return X, y

    def train(self, examples: Sequence[dict], model_path: Path, c1=0.05, c2=0.05, max_iterations=150) -> dict:
        import sklearn_crfsuite
        model_path = Path(model_path)
        model_path.parent.mkdir(parents=True, exist_ok=True)
        X, y = self._docs_xy(examples)
        self.crf = sklearn_crfsuite.CRF(algorithm="lbfgs", c1=c1, c2=c2, max_iterations=max_iterations,
                                        all_possible_transitions=True, model_filename=str(model_path))
        self.crf.fit(X, y)
        meta = {"n_train_sentences": len(X), "c1": c1, "c2": c2, "max_iterations": max_iterations,
                "labels": sorted(self.crf.classes_)}
        model_path.with_suffix(".json").write_text(json.dumps(meta, indent=2))
        return meta

    def load(self, model_path: Path) -> "CRFNER":
        import sklearn_crfsuite
        model_path = Path(model_path)
        if not model_path.exists():
            raise ModelNotTrainedError(f"CRF model not found at {model_path}. "
                                       "Run: python -m nlu.training.train_ner")
        self.crf = sklearn_crfsuite.CRF(model_filename=str(model_path))
        return self

    def predict(self, doc: Doc) -> List[Entity]:
        if self.crf is None:
            raise ModelNotTrainedError("CRF model not loaded")
        if not doc.tokens:
            return []
        feats = doc_to_features(doc, self.lex)
        tags = self.crf.predict_single(feats)
        marg = self.crf.predict_marginals_single(feats)
        out = []
        for s, e, etype, i, j in bio_to_spans(doc, tags):
            p = sum(marg[k].get(tags[k], 0.0) for k in range(i, j)) / (j - i)
            ent = _ent(doc, s, e, etype, method="crf")
            ent.confidence, ent.confidence_type = round(p, 4), "crf_marginal_mean"
            out.append(ent)
        return out


# ============================================================================ hybrid
class HybridNER:
    MODES = ("hybrid", "rules_only", "crf_only")

    def __init__(self, rules: RuleBasedNER, crf: Optional[CRFNER], mode: str = "hybrid"):
        if mode not in self.MODES:
            raise ValueError(f"mode must be one of {self.MODES}")
        if mode != "rules_only" and crf is None:
            raise ModelNotTrainedError("NER mode %r needs a CRF model" % mode)
        self.rules, self.crf, self.mode = rules, crf, mode
        cfg = rules.cfg
        self._no_person = (set(cfg["pronouns"]["self"]) | set(cfg["pronouns"]["third_person"]) | set(cfg["determiners"])
                           | {w for p in rules.index.actions for w in p})
        self._temporal = {"today", "tomorrow", "yesterday", "tonight", "week", "weeks", "month", "months", "year", "years",
                          "quarter", "day", "days", "weekend", "end", "next", "this", "last", "monday", "tuesday", "wednesday",
                          "thursday", "friday", "saturday", "sunday"}

    def _plausible(self, c: Entity, doc: Doc) -> bool:
        """Cheap sanity check on statistical-only entities (never on rule entities)."""
        words = {t.norm for t in doc.tokens if t.start >= c.start and t.end <= c.end}
        if c.type == "EFFECTIVE_DATE":
            return any(ch.isdigit() for ch in c.text) or bool(words & self._temporal)
        if c.type == "PERSON":
            return not (words & self._no_person)
        if c.type == "EMPLOYEE_IDENTIFIER":
            return any(ch.isdigit() for ch in c.text)
        return True

    def extract(self, doc: Doc) -> Tuple[List[Entity], List[dict]]:
        conflicts: List[dict] = []
        selected: List[Entity] = []
        if self.mode in ("hybrid", "rules_only"):
            cands = self.rules.extract(doc)
            keyed = sorted(cands, key=lambda c: (-(doc.span_to_tokens(c.start, c.end)[1] - doc.span_to_tokens(c.start, c.end)[0]),
                                                 PRIORITY[c.type], 0 if c.match != "fuzzy" else 1, c.start))
            for c in keyed:
                clash = next((s for s in selected if s.overlaps(c)), None)
                if clash is None:
                    selected.append(c)
                else:
                    tie = (c.type != clash.type and
                           (doc.span_to_tokens(c.start, c.end) == doc.span_to_tokens(clash.start, clash.end)))
                    conflicts.append({"kept": clash, "discarded": c, "source": "rule",
                                      "reason": "same-length tie broken by type priority" if tie else "longer/higher-priority span wins",
                                      "significant": tie})
        if self.mode in ("hybrid", "crf_only"):
            for c in self.crf.predict(doc):
                clash = next((s for s in selected if s.overlaps(c)), None)
                if clash is None:
                    if self._plausible(c, doc):
                        selected.append(c)
                    else:
                        conflicts.append({"kept": None, "discarded": c, "source": "crf",
                                          "reason": "failed plausibility check", "significant": False})
                else:
                    conflicts.append({"kept": clash, "discarded": c, "source": "crf",
                                      "reason": "rule-based entity takes precedence over CRF",
                                      "significant": c.type != clash.type and (c.confidence or 0) >= 0.7})
        selected.sort(key=lambda e: (e.start, e.end))
        return selected, conflicts
