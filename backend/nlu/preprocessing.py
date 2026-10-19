"""Text preprocessing: offset-preserving tokenisation, typo correction, negation helpers."""
from __future__ import annotations

import difflib
import re
from bisect import bisect_right
from dataclasses import dataclass, field
from typing import Collection, List, Optional, Tuple

_TOKEN_RE = re.compile(r"\d{1,2}/\d{1,2}(?:/\d{2,4})?|\w+(?:-\w+)*(?:['’]\w+)?|[^\w\s]", re.UNICODE)
_POSSESSIVE_RE = re.compile(r"['’][sS]$")
CLAUSE_PUNCT = set(".,;:!?")


@dataclass
class Token:
    text: str
    start: int
    end: int
    index: int = 0
    norm: str = ""
    corr: Optional[str] = None   # typo-corrected form (closed lexicon only), never used for spans

    @property
    def match(self) -> str:
        return self.corr or self.norm

    @property
    def is_punct(self) -> bool:
        return not any(c.isalnum() for c in self.text)


def tokenize(text: str) -> List[Token]:
    """Regex tokenizer with character offsets. Possessive 's is split off ("Ananya's" -> "Ananya", "'s")."""
    tokens: List[Token] = []
    for m in _TOKEN_RE.finditer(text):
        s, e, t = m.start(), m.end(), m.group()
        if len(t) > 2 and _POSSESSIVE_RE.search(t):
            tokens.append(Token(t[:-2], s, e - 2))
            tokens.append(Token(t[-2:], e - 2, e))
        else:
            tokens.append(Token(t, s, e))
    for i, tok in enumerate(tokens):
        tok.index = i
        tok.norm = tok.text.lower().replace("’", "'")
    return tokens


@dataclass
class Doc:
    text: str
    tokens: List[Token]
    clean: str = ""
    _starts: List[int] = field(default_factory=list, repr=False)

    def __post_init__(self):
        parts, pos = [], 0
        self._starts = []
        for t in self.tokens:
            self._starts.append(pos)
            parts.append(t.match)
            pos += len(t.match) + 1
        self.clean = " ".join(parts)

    def clean_pos_to_token(self, pos: int) -> int:
        return max(0, bisect_right(self._starts, pos) - 1)

    def span_to_tokens(self, start: int, end: int) -> Tuple[int, int]:
        """Token index range [i, j) of tokens lying inside the character span."""
        idx = [t.index for t in self.tokens if t.start >= start and t.end <= end]
        if not idx:
            return (0, 0)
        return (idx[0], idx[-1] + 1)


def correct_tokens(tokens: List[Token], lexicon: Collection[str],
                   cutoff: float = 0.8, min_len: int = 5) -> None:
    """Fuzzy-correct tokens against a small closed verb/noun lexicon (sets Token.corr only)."""
    lex = set(lexicon)
    pool = sorted(lex)
    for tok in tokens:
        w = tok.norm
        if len(w) < min_len or not w.isalpha() or w in lex:
            continue
        if any(w.startswith(l) and len(w) - len(l) <= 3 for l in lex):
            continue  # regular inflection of a lexicon word (revoked, requests, ...)
        if tok.text[0].isupper() and tok.index > 0 and not tokens[tok.index - 1].text in CLAUSE_PUNCT:
            continue  # capitalised mid-sentence: probably a name
        best = difflib.get_close_matches(w, pool, n=1, cutoff=cutoff)
        if best and best[0][0] == w[0] and abs(len(best[0]) - len(w)) <= 2:
            tok.corr = best[0]


def preprocess(text: str, typo_lexicon: Collection[str] = ()) -> Doc:
    tokens = tokenize(text)
    if typo_lexicon:
        correct_tokens(tokens, typo_lexicon)
    return Doc(text, tokens)


def negated_at(tokens: List[Token], idx: int, negators: Collection[str],
               break_words: Collection[str] = (), window: int = 3) -> bool:
    """True if a negator occurs within `window` word tokens before idx, without crossing a clause break."""
    j, steps = idx - 1, 0
    while j >= 0 and steps < window:
        t = tokens[j]
        if t.text in CLAUSE_PUNCT or t.norm in break_words:
            return False
        if t.norm in negators:
            return True
        if not t.is_punct:
            steps += 1
        j -= 1
    return False
