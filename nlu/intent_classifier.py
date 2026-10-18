"""Intent classification: explainable rule baseline, custom TF-IDF + multinomial Naive Bayes, hybrid policy.

The Naive Bayes model and TF-IDF weighting are implemented from scratch (no sklearn vectoriser/classifier).
"""
from __future__ import annotations

import json
import math
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from .features import Lexicons
from .preprocessing import Doc, negated_at, preprocess
from .schemas import INTENTS, Entity, ModelNotTrainedError
from .slot_filler import assign_department_roles

LABELS = [i for i in INTENTS]


# ============================================================================ rules
class RuleBasedIntentClassifier:
    def __init__(self, patterns_cfg: dict):
        self.cfg = patterns_cfg
        self.cues = []
        for intent, lst in patterns_cfg["intent_cues"].items():
            for c in lst:
                self.cues.append((intent, re.compile(c["regex"], re.I), c["weight"], c.get("suppresses", []), c["regex"]))
        self.unsupported = [re.compile(p, re.I) for p in patterns_cfg["unsupported_cues"]]
        self.negators = set(patterns_cfg["negators"])
        self.breaks = set(patterns_cfg["clause_break_words"])
        self.window = patterns_cfg["negation_window"]
        th = patterns_cfg["intent_thresholds"]
        self.min_score, self.conflict_ratio = th["min_score"], th["conflict_ratio"]

    def classify(self, doc: Doc, entities: Optional[Sequence[Entity]] = None) -> dict:
        scores: Dict[str, float] = defaultdict(float)
        evidence, negated_scores, suppress = [], defaultdict(float), []
        matches = []
        for intent, rx, w, supp, raw in self.cues:
            m = rx.search(doc.clean)
            if not m:
                continue
            ti = doc.clean_pos_to_token(m.start())
            neg = negated_at(doc.tokens, ti, self.negators, self.breaks, self.window)
            matches.append((intent, m.group().strip(), w, supp, neg))
        strong_negated = any(neg and w >= 2.5 for _, _, w, _, neg in matches)
        for intent, cue, w, supp, neg in matches:
            evidence.append({"intent": intent, "cue": cue, "weight": w, "negated": neg})
            if neg:
                negated_scores[intent] += w
            elif strong_negated and w < 2:
                continue  # weak cues may not override an explicitly negated action
            else:
                scores[intent] += w
                suppress.extend(supp)
        for s in set(suppress):
            scores[s] *= 0.3
        # lifecycle events subsume an accompanying access request (e.g. "new hire needs access to Jira")
        if scores.get("JOINER", 0) >= 2 and scores.get("ACCESS_REQUEST"):
            scores["ACCESS_REQUEST"] *= 0.3
        # entity context: a source ("from X") and a target ("to Y") department => move
        hint = None
        if entities:
            depts = [e for e in entities if e.type == "DEPARTMENT"]
            roles = assign_department_roles(doc, depts, self.cfg)
            if "source" in roles and "target" in roles:
                scores["MOVER"] += 3
                scores["JOINER"] *= 0.4
                scores["LEAVER"] *= 0.4
                hint = "source+target department cues"
                evidence.append({"intent": "MOVER", "cue": hint, "weight": 3, "negated": False})
        scores = {k: round(v, 3) for k, v in scores.items() if v > 0}

        ranked = sorted(scores.items(), key=lambda kv: (-kv[1], LABELS.index(kv[0])))
        unsupported = any(rx.search(doc.clean) for rx in self.unsupported)
        negation_present = any(t.norm in self.negators for t in doc.tokens)
        neg_candidates = sorted(k for k, v in negated_scores.items() if v >= 2.5 and k not in scores)
        out = {"label": "UNKNOWN", "confidence": None, "confidence_type": None, "scores": scores,
               "evidence": evidence, "conflict": False, "candidates": [], "negated_candidates": neg_candidates,
               "negation_present": negation_present, "unsupported": False, "reason": None}
        top = ranked[0] if ranked else (None, 0.0)
        if top[0] is None or top[1] < self.min_score or (unsupported and top[1] < 2.5):
            out["unsupported"] = unsupported
            out["reason"] = ("unsupported" if unsupported else "negated" if neg_candidates else "no_cue")
            return out
        second = ranked[1] if len(ranked) > 1 else (None, 0.0)
        out["label"] = top[0]
        out["confidence"] = round(top[1] / (top[1] + second[1] + 1.0), 3)
        out["confidence_type"] = "heuristic"
        if second[0] and second[1] >= self.conflict_ratio * top[1] and second[1] >= self.min_score:
            out["conflict"] = True
            out["candidates"] = [{"label": k, "score": v} for k, v in ranked[:3]]
        return out


# ============================================================================ Naive Bayes
class NaiveBayesIntentClassifier:
    """Multinomial NB over manually computed TF-IDF features (unigrams + bigrams).

    tf = 1 + ln(count); idf = ln((1+N)/(1+df)) + 1; vectors L2-normalised; Laplace smoothing alpha.
    Outputs are NB posteriors: useful for ranking, NOT calibrated probabilities.
    """

    def __init__(self, lexicons: Lexicons, entities_cfg: dict, typo_lexicon: Sequence[str] = (), alpha: float = 0.1):
        self.lex_mask, self.exact_mask = lexicons.mask_maps(entities_cfg)
        self.typo_lexicon = list(typo_lexicon)
        self.alpha = alpha
        self.vocab: Dict[str, int] = {}
        self.idf: List[float] = []
        self.classes: List[str] = []
        self.log_prior: Dict[str, float] = {}
        self.log_lik: Dict[str, List[float]] = {}

    # ---- features
    def tokens(self, doc: Doc) -> List[str]:
        out = []
        for t in doc.tokens:
            if t.is_punct:
                if t.text == "?":
                    out.append("<q>")
                continue
            prev = doc.tokens[t.index - 1].text if t.index else ""
            sent_start = t.index == 0 or prev in ".!?"
            if t.text in self.exact_mask:
                out.append(self.exact_mask[t.text])
            elif t.norm in self.lex_mask:
                out.append(self.lex_mask[t.norm])
            elif any(c.isdigit() for c in t.text):
                out.append("<num>")
            elif t.text[0].isupper() and not sent_start and t.text != "I" and not t.corr and t.norm not in self.typo_lexicon:
                out.append("<cap>")
            else:
                out.append(t.match)
        return out

    def ngrams(self, doc: Doc) -> List[str]:
        w = self.tokens(doc)
        return w + [a + "_" + b for a, b in zip(w, w[1:])]

    def _vec(self, grams: List[str]) -> Dict[int, float]:
        cnt = Counter(g for g in grams if g in self.vocab)
        v = {self.vocab[g]: (1 + math.log(c)) * self.idf[self.vocab[g]] for g, c in cnt.items()}
        norm = math.sqrt(sum(x * x for x in v.values())) or 1.0
        return {k: x / norm for k, x in v.items()}

    # ---- training
    def train(self, texts: Sequence[str], labels: Sequence[str]) -> dict:
        grams = [self.ngrams(preprocess(t, self.typo_lexicon)) for t in texts]
        df = Counter(g for gs in grams for g in set(gs))
        self.vocab = {g: i for i, g in enumerate(sorted(df))}
        N = len(texts)
        self.idf = [math.log((1 + N) / (1 + df[g])) + 1 for g in sorted(df)]
        self.classes = sorted(set(labels))
        sums = {c: [0.0] * len(self.vocab) for c in self.classes}
        n_c = Counter(labels)
        for gs, y in zip(grams, labels):
            for k, x in self._vec(gs).items():
                sums[y][k] += x
        V = len(self.vocab)
        for c in self.classes:
            tot = sum(sums[c])
            self.log_prior[c] = math.log(n_c[c] / N)
            self.log_lik[c] = [math.log((s + self.alpha) / (tot + self.alpha * V)) for s in sums[c]]
        return {"n_train": N, "vocab_size": V, "classes": self.classes, "alpha": self.alpha}

    # ---- inference
    def predict(self, doc: Doc) -> dict:
        if not self.classes:
            raise ModelNotTrainedError("Naive Bayes intent model is not trained/loaded")
        v = self._vec(self.ngrams(doc))
        raw = {c: self.log_prior[c] + sum(x * self.log_lik[c][k] for k, x in v.items()) for c in self.classes}
        m = max(raw.values())
        exp = {c: math.exp(s - m) for c, s in raw.items()}
        z = sum(exp.values())
        probs = {c: round(e / z, 4) for c, e in exp.items()}
        label = max(probs, key=probs.get)
        return {"label": label, "probability": probs[label], "probabilities": probs,
                "confidence_type": "naive_bayes_posterior_uncalibrated"}

    # ---- persistence
    def save(self, path: Path) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps({"alpha": self.alpha, "vocab": self.vocab, "idf": self.idf,
                                          "classes": self.classes, "log_prior": self.log_prior,
                                          "log_lik": self.log_lik}))

    def load(self, path: Path) -> "NaiveBayesIntentClassifier":
        path = Path(path)
        if not path.exists():
            raise ModelNotTrainedError(f"Naive Bayes model not found at {path}. Run: python -m nlu.training.train_intent")
        d = json.loads(path.read_text())
        self.alpha, self.vocab, self.idf = d["alpha"], d["vocab"], d["idf"]
        self.classes, self.log_prior, self.log_lik = d["classes"], d["log_prior"], d["log_lik"]
        return self


# ============================================================================ hybrid
class HybridIntentClassifier:
    """Policy: the rule baseline decides whenever it fires; Naive Bayes only fills the gap when no rule
    cue fired (never overrides negation or unsupported-request detection)."""
    MODES = ("hybrid", "rules_only", "nb_only")

    def __init__(self, rules: RuleBasedIntentClassifier, nb: Optional[NaiveBayesIntentClassifier],
                 patterns_cfg: dict, mode: str = "hybrid"):
        if mode not in self.MODES:
            raise ValueError(f"mode must be one of {self.MODES}")
        if mode != "rules_only" and nb is None:
            raise ModelNotTrainedError("intent mode %r needs a Naive Bayes model" % mode)
        self.rules, self.nb, self.mode = rules, nb, mode
        th = patterns_cfg["intent_thresholds"]
        self.nb_min, self.nb_dis = th["nb_min_probability"], th["nb_disagreement_probability"]

    def classify(self, doc: Doc, entities: Optional[Sequence[Entity]] = None) -> dict:
        r = self.rules.classify(doc, entities) if self.mode != "nb_only" else None
        n = self.nb.predict(doc) if self.mode != "rules_only" else None
        if self.mode == "rules_only":
            r["method"] = "rule_based"
            return r
        if self.mode == "nb_only":
            return {"label": n["label"], "confidence": n["probability"], "confidence_type": n["confidence_type"],
                    "method": "naive_bayes", "scores": n["probabilities"], "evidence": [], "conflict": False,
                    "candidates": [], "negated_candidates": [], "negation_present": False,
                    "unsupported": False, "reason": None, "statistical": n}
        r["statistical"] = n
        if r["label"] != "UNKNOWN":
            r["method"] = "rule_based"
            r["model_disagreement"] = bool(n["label"] != r["label"] and n["probability"] >= self.nb_dis)
            return r
        blocked = r["negation_present"] or r["unsupported"] or r["reason"] in ("negated", "unsupported")
        if (not blocked) and n["label"] != "UNKNOWN" and n["probability"] >= self.nb_min:
            r.update(label=n["label"], confidence=n["probability"], confidence_type=n["confidence_type"],
                     method="naive_bayes", reason=None)
            return r
        r["method"] = "rule_based"
        return r
