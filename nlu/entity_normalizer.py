"""Dictionary index (aliases, fuzzy lookup), entity normalisation and temporal resolution."""
from __future__ import annotations

import calendar
import difflib
import re
from dataclasses import dataclass
from datetime import date, timedelta
from typing import Any, Dict, List, Optional, Tuple

from .preprocessing import tokenize
from .schemas import Entity

WEEKDAYS = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]
MONTHS = {"jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6, "jul": 7, "aug": 8,
          "sep": 9, "oct": 10, "nov": 11, "dec": 12}
NUMBER_WORDS = {"a": 1, "an": 1, "one": 1, "two": 2, "three": 3, "four": 4, "five": 5,
                "six": 6, "seven": 7, "eight": 8, "nine": 9, "ten": 10, "a couple of": 2}


@dataclass
class DictEntry:
    tokens: Tuple[str, ...]        # normalised (lower-case) tokens
    raw_tokens: Tuple[str, ...]    # original-case tokens
    case_sensitive: bool
    etype: str
    canonical: str


class DictionaryIndex:
    """Configurable department / application / role dictionaries plus action phrases."""

    def __init__(self, entities_cfg: dict, patterns_cfg: dict):
        cs = set(entities_cfg.get("case_sensitive_aliases", []))
        self.entries: List[DictEntry] = []
        self._exact: Dict[Tuple[str, Tuple[str, ...]], str] = {}
        self._exact_cs: Dict[Tuple[str, Tuple[str, ...]], str] = {}
        for etype in ("DEPARTMENT", "APPLICATION", "ACCESS_ROLE"):
            for canonical, spec in entities_cfg.get(etype, {}).items():
                for alias in [canonical] + list(spec.get("aliases", [])):
                    toks = tokenize(alias)
                    norm = tuple(t.norm for t in toks)
                    raw = tuple(t.text for t in toks)
                    sens = alias in cs
                    self.entries.append(DictEntry(norm, raw, sens, etype, canonical))
                    (self._exact_cs if sens else self._exact)[(etype, raw if sens else norm)] = canonical
        self.actions: Dict[Tuple[str, ...], str] = {}
        for code, phrases in patterns_cfg["actions"].items():
            for p in phrases:
                self.actions[tuple(t.norm for t in tokenize(p))] = code
        fz = patterns_cfg.get("fuzzy", {})
        self.fz_min_ratio = fz.get("min_ratio", 0.84)
        self.fz_min_len = fz.get("min_length", 5)
        self.fz_max_diff = fz.get("max_length_diff", 2)
        self.fz_types = set(fz.get("types", []))
        self.fz_stop = set(fz.get("stoplist", []))
        self._fuzzy_vocab = [(e.tokens[0], e.etype, e.canonical) for e in self.entries
                             if len(e.tokens) == 1 and not e.case_sensitive
                             and e.etype in self.fz_types and len(e.tokens[0]) >= self.fz_min_len]

    def exact_lookup(self, etype: str, surface: str) -> Optional[str]:
        toks = tokenize(surface)
        raw = tuple(t.text for t in toks)
        norm = tuple(t.norm for t in toks)
        return self._exact_cs.get((etype, raw)) or self._exact.get((etype, norm))

    def fuzzy_lookup(self, etype: Optional[str], word: str) -> Optional[Tuple[str, str, float]]:
        """Best fuzzy match of a single word -> (canonical, etype, ratio) or None."""
        w = word.lower()
        if len(w) < self.fz_min_len or not w.isalpha() or w in self.fz_stop:
            return None
        best = None
        for cand, ct, canon in self._fuzzy_vocab:
            if etype and ct != etype:
                continue
            if cand == w or cand[0] != w[0] or abs(len(cand) - len(w)) > self.fz_max_diff:
                continue
            r = difflib.SequenceMatcher(None, w, cand).ratio()
            if r >= self.fz_min_ratio and (best is None or r > best[2]):
                best = (canon, ct, r)
        return best

    def action_lookup(self, surface: str) -> Optional[str]:
        return self.actions.get(tuple(t.norm for t in tokenize(surface)))


# ----------------------------------------------------------------------------- dates
def _add_months(d: date, n: int) -> date:
    m = d.month - 1 + n
    y, m = d.year + m // 12, m % 12 + 1
    return date(y, m, min(d.day, calendar.monthrange(y, m)[1]))


def _eom(y: int, m: int) -> date:
    return date(y, m, calendar.monthrange(y, m)[1])


def _result(expr, value=None, kind="unresolved", reason=None, candidates=None, ref=None):
    d = {"expression": expr, "value": value.isoformat() if value else None,
         "resolved": value is not None, "kind": kind}
    if reason:
        d["reason"] = reason
    if candidates:
        d["candidates"] = [c.isoformat() for c in candidates]
        d["ambiguous"] = True
    if value is not None and ref is not None and value < ref:
        d["in_past"] = True
    return d


def normalize_date(expr: str, ref: date) -> Dict[str, Any]:
    """Resolve a temporal expression against `ref`; never guess when the expression is vague/ambiguous.

    Conventions: bare weekday = first such day strictly after `ref`; "next <weekday>" is ambiguous when
    that day is still in the current ISO week; day/month without year = next occurrence on/after `ref`;
    numeric dates are DD/MM/YYYY.
    """
    s = re.sub(r"\s+", " ", expr.lower().strip())
    s = re.sub(r"^(?:(?:at|by|on)\s+)+", "", s)
    s = re.sub(r"^the\s+(?=end)", "", s)
    R = lambda *a, **k: _result(expr, *a, ref=ref, **k)

    m = re.fullmatch(r"(\d{4})-(\d{2})-(\d{2})", s)
    if m:
        try:
            return R(date(int(m[1]), int(m[2]), int(m[3])), kind="absolute")
        except ValueError:
            return R(reason="invalid_date")
    m = re.fullmatch(r"(\d{1,2})/(\d{1,2})/(\d{2,4})", s)
    if m:
        y = int(m[3]) + (2000 if int(m[3]) < 100 else 0)
        try:
            return R(date(y, int(m[2]), int(m[1])), kind="absolute")
        except ValueError:
            return R(reason="invalid_date")
    mon = r"(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.?"
    m = re.fullmatch(r"(\d{1,2})(?:st|nd|rd|th)?\s+(?:of\s+)?" + mon + r"(?:,?\s+(\d{4}))?", s) or None
    dm = None
    if m:
        dm = (int(m[1]), MONTHS[m[2]], m[3])
    else:
        m = re.fullmatch(mon + r"\s+(\d{1,2})(?:st|nd|rd|th)?(?:,?\s+(\d{4}))?", s)
        if m:
            dm = (int(m[2]), MONTHS[m[1]], m[3])
    if dm:
        day, month, year = dm
        try:
            if year:
                return R(date(int(year), month, day), kind="absolute")
            cand = date(ref.year, month, day)
            if cand < ref:
                cand = date(ref.year + 1, month, day)
            return R(cand, kind="absolute_no_year")
        except ValueError:
            return R(reason="invalid_date")

    if s in ("today", "tonight"):
        return R(ref, kind="relative_day")
    if s == "tomorrow":
        return R(ref + timedelta(days=1), kind="relative_day")
    if s == "yesterday":
        return R(ref - timedelta(days=1), kind="relative_day")

    m = re.fullmatch(r"(?:(this|next|last|coming)\s+)?(" + "|".join(WEEKDAYS) + ")", s)
    if m:
        mod, wd = m[1], WEEKDAYS.index(m[2])
        ahead = (wd - ref.weekday()) % 7
        if mod in (None, "coming"):
            return R(ref + timedelta(days=ahead or 7), kind="weekday")
        if mod == "last":
            back = (ref.weekday() - wd) % 7
            return R(ref - timedelta(days=back or 7), kind="weekday")
        if mod == "this":
            d = ref + timedelta(days=ahead)
            if d.isocalendar()[:2] == ref.isocalendar()[:2]:
                return R(d, kind="weekday")
            return R(reason="ambiguous_weekday", candidates=[d])
        d = ref + timedelta(days=ahead or 7)  # next
        if d.isocalendar()[:2] == ref.isocalendar()[:2]:
            return R(reason="ambiguous_next_weekday", candidates=[d, d + timedelta(days=7)])
        return R(d, kind="weekday")

    m = re.fullmatch(r"end of (?:the |this |next )?(month|week|quarter|year)", s)
    if m:
        unit = m[1]
        nxt = "next" in s
        if unit == "week":
            return R(reason="end_of_week_undefined")
        if unit == "month":
            base = _add_months(ref.replace(day=1), 1 if nxt else 0)
            return R(_eom(base.year, base.month), kind="end_of_period")
        if unit == "quarter":
            q_end_month = ((ref.month - 1) // 3 + 1) * 3
            base = _add_months(date(ref.year, q_end_month, 1), 3 if nxt else 0)
            return R(_eom(base.year, base.month), kind="end_of_period")
        return R(date(ref.year + (1 if nxt else 0), 12, 31), kind="end_of_period")

    m = re.fullmatch(r"in (\d+|an?|one|two|three|four|five|six|seven|eight|nine|ten|a couple of|a few) (day|week|month)s?", s)
    if m:
        if m[1] == "a few":
            return R(reason="vague_quantity")
        n = int(m[1]) if m[1].isdigit() else NUMBER_WORDS[m[1]]
        if m[2] == "day":
            return R(ref + timedelta(days=n), kind="relative_offset")
        if m[2] == "week":
            return R(ref + timedelta(weeks=n), kind="relative_offset")
        return R(_add_months(ref, n), kind="relative_offset")

    if re.fullmatch(r"(?:next|this|last|following) (?:week|month|quarter|year|weekend)", s):
        return R(reason="period_without_specific_day")
    return R(reason="unrecognised_expression")


# ----------------------------------------------------------------------------- normaliser
class EntityNormalizer:
    def __init__(self, index: DictionaryIndex):
        self.index = index

    def normalize(self, ent: Entity, ref: date) -> None:
        """Fill `normalized` (and `match`) when the NER stage did not already do so."""
        t = ent.type
        if t == "PERSON":
            ent.normalized = re.sub(r"\s+", " ", ent.text).strip()
        elif t == "EMPLOYEE_IDENTIFIER":
            m = re.search(r"\d{3,}", ent.text)
            ent.normalized = re.sub(r"[-_\s]", "", ent.text).upper() if m else ent.text.upper()
        elif t == "EFFECTIVE_DATE":
            ent.normalized = normalize_date(ent.text, ref)
        elif t == "REASON":
            ent.normalized = re.sub(r"\s+", " ", ent.text).strip()
        elif t == "ACTION":
            if ent.normalized is None:
                ent.normalized = self.index.action_lookup(ent.text)
        elif t in ("DEPARTMENT", "APPLICATION", "ACCESS_ROLE") and ent.normalized is None:
            canon = self.index.exact_lookup(t, ent.text)
            if canon:
                ent.normalized, ent.match = canon, "exact"
            elif " " not in ent.text.strip():
                fz = self.index.fuzzy_lookup(t, ent.text) if t in self.index.fz_types else None
                if fz:
                    ent.normalized, ent.match = fz[0], "fuzzy"
