"""Fuzzy name suggestions for the assistant (used only for voice input, and only when the exact lookup found nobody).

Speech recognition hears "Cinder Khan" as "Sender Khan". The directory lookup is a plain substring match, so that returns
nothing. Here we rank the directory's people by how close they are to what was heard and let the user pick; we never
auto-select, so a wrong guess cannot reach the policy engine without a click.

Scoring, per word of the heard name:
  * Levenshtein similarity (1 - edits / longest length) against every word of the person's name and e-mail local part;
  * if the optional `jellyfish` package is installed, words with the same Metaphone key count as at least 0.85 similar
    ("Sender" / "Cinder" both reduce to SNTR), which catches sound-alikes that edit distance under-rates.
The person's score is the mean of those per-word bests. A person is only suggested when EVERY heard word has a decent
match (so "Sender Khan" never suggests "Zoya Khan" on the surname alone) and the mean clears MIN_SCORE.
"""
from __future__ import annotations

import re
from typing import Iterable

try:                                    # optional: without it we simply fall back to edit distance
    import jellyfish
except Exception:                       # pragma: no cover
    jellyfish = None

LIMIT = 4
MIN_SCORE = 0.65        # mean per-word similarity needed to be suggested at all
MIN_WORD = 0.60         # every heard word must reach at least this against some word of the person
PHONETIC_FLOOR = 0.85

_WORD = re.compile(r"[a-z]+")


def words(s: str) -> list[str]:
    return _WORD.findall((s or "").lower())


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a or not b:
        return max(len(a), len(b))
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def similarity(a: str, b: str) -> float:
    return 1.0 - levenshtein(a, b) / max(len(a), len(b), 1)


def _phonetic(w: str) -> str:
    if jellyfish is None or len(w) < 3:
        return ""
    try:
        return jellyfish.metaphone(w)
    except Exception:                   # pragma: no cover
        return ""


def word_score(heard: str, known: str) -> float:
    s = similarity(heard, known)
    if s < PHONETIC_FLOOR:
        p = _phonetic(heard)
        if p and p == _phonetic(known):
            return PHONETIC_FLOOR
    return s


def score(heard: list[str], full_name: str, email: str) -> float | None:
    """Mean best per-word similarity, or None when some heard word has no plausible counterpart."""
    known = words(full_name) + words((email or "").split("@")[0])
    if not heard or not known:
        return None
    best = [max(word_score(h, k) for k in known) for h in heard]
    if min(best) < MIN_WORD:
        return None
    mean = sum(best) / len(best)
    return mean if mean >= MIN_SCORE else None


def rank(person: str, people: Iterable[tuple[str, str, str]], limit: int = LIMIT) -> list[dict]:
    """people: (employee_id, full_name, email). Returns up to `limit` best matches, best first."""
    heard = [w for w in words(person) if len(w) >= 2]
    whole = " ".join(heard)
    out = []
    for emp_id, name, email in people:
        s = score(heard, name, email)
        if s is not None:
            out.append((s, similarity(whole, " ".join(words(name))), name.lower(),
                        {"employee_id": emp_id, "full_name": name, "email": email, "score": round(s, 3)}))
    out.sort(key=lambda t: (-t[0], -t[1], t[2]))
    return [o[3] for o in out[:limit]]