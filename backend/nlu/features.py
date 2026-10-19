"""Token-level feature extraction for the CRF NER (hand-written, no pretrained resources)."""
from __future__ import annotations

import re
from typing import Dict, List, Set

from .preprocessing import Doc, tokenize

_MONTHS = {"january", "february", "march", "april", "may", "june", "july", "august", "september",
           "october", "november", "december", "jan", "feb", "mar", "apr", "jun", "jul", "aug",
           "sep", "sept", "oct", "nov", "dec"}
_WEEKDAYS = {"monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"}


def word_shape(w: str) -> str:
    s = re.sub(r"[A-Z]", "X", w)
    s = re.sub(r"[a-z]", "x", s)
    s = re.sub(r"\d", "d", s)
    return re.sub(r"(.)\1{2,}", r"\1\1", s)


class Lexicons:
    """Token-level lexicons derived from the local configuration."""

    def __init__(self, entities_cfg: dict, patterns_cfg: dict):
        def toks(etype):
            out: Set[str] = set()
            for canon, spec in entities_cfg.get(etype, {}).items():
                for a in [canon] + spec.get("aliases", []):
                    out.update(t.norm for t in tokenize(a) if not t.is_punct)
            return out
        self.cats: Dict[str, Set[str]] = {
            "dept": toks("DEPARTMENT"), "app": toks("APPLICATION"), "role": toks("ACCESS_ROLE"),
            "action": {t.norm for ps in patterns_cfg["actions"].values() for p in ps for t in tokenize(p)},
            "month": _MONTHS, "weekday": _WEEKDAYS,
            "reasoncue": {"because", "due", "owing", "part", "account"},
            "src": set(patterns_cfg["department_role_cues"]["source"]),
            "tgt": set(patterns_cfg["department_role_cues"]["target"]),
            "neg": set(patterns_cfg["negators"]),
            "self": set(patterns_cfg["pronouns"]["self"]),
            "third": set(patterns_cfg["pronouns"]["third_person"]),
            "det": set(patterns_cfg["determiners"]),
        }
        self.cats["action"] -= {"to"}
        # tokens that are ambiguous with ordinary words get no unconditional dictionary flag
        self.cats["dept"] -= {"and", "support"}

    def categories(self, w: str) -> List[str]:
        return [c for c, s in self.cats.items() if w in s]

    def mask_maps(self, entities_cfg: dict):
        """(lowercase map, case-sensitive map) token -> mask label for intent features."""
        lower, exact = {}, {}
        cs = set(entities_cfg.get("case_sensitive_aliases", []))
        for etype, label in (("DEPARTMENT", "<dept>"), ("APPLICATION", "<app>"), ("ACCESS_ROLE", "<role>")):
            for canon, spec in entities_cfg.get(etype, {}).items():
                for a in [canon] + spec.get("aliases", []):
                    ts = tokenize(a)
                    if len(ts) != 1:
                        for t in ts:
                            if not t.is_punct and len(t.norm) > 3:
                                lower.setdefault(t.norm, label)
                        continue
                    (exact if a in cs else lower)[ts[0].text if a in cs else ts[0].norm] = label
        return lower, exact


def _tok_feats(doc: Doc, i: int, lex: Lexicons, prefix: str, full: bool) -> Dict:
    t = doc.tokens[i]
    w, lw = t.text, t.norm
    f = {prefix + "lower": lw, prefix + "title": w.istitle(), prefix + "upper": w.isupper(),
         prefix + "shape": word_shape(w), prefix + "digit": w.isdigit(), prefix + "punct": t.is_punct}
    for c in lex.categories(t.match):
        f[prefix + "cat:" + c] = True
    if full:
        f.update({"suffix3": lw[-3:], "suffix2": lw[-2:], "suffix4": lw[-4:], "prefix1": lw[:1],
                  "prefix2": lw[:2], "prefix3": lw[:3], "prefix4": lw[:4], "has_digit": any(c.isdigit() for c in w),
                  "has_hyphen": "-" in w, "len": min(len(w), 12), "match": t.match,
                  "is_possessive": w in ("'s", "’s")})
    return f


def token_features(doc: Doc, i: int, lex: Lexicons) -> Dict:
    f = {"bias": 1.0, "BOS": i == 0, "EOS": i == len(doc.tokens) - 1}
    f.update(_tok_feats(doc, i, lex, "", True))
    for off in (-2, -1, 1, 2):
        j = i + off
        if 0 <= j < len(doc.tokens):
            f.update(_tok_feats(doc, j, lex, f"{off:+d}:", False))
    if i > 0:
        f["bi-:" ] = doc.tokens[i - 1].norm + "|" + doc.tokens[i].norm
    if i + 1 < len(doc.tokens):
        f["bi+:"] = doc.tokens[i].norm + "|" + doc.tokens[i + 1].norm
    # next token is possessive 's (strong PERSON cue)
    if i + 1 < len(doc.tokens) and doc.tokens[i + 1].text in ("'s", "’s"):
        f["next_possessive"] = True
    return f


def doc_to_features(doc: Doc, lex: Lexicons) -> List[Dict]:
    return [token_features(doc, i, lex) for i in range(len(doc.tokens))]
