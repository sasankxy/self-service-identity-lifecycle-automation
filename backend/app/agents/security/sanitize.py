"""Input normalisation applied to every untrusted string before any agent sees it.

* NFKC folds compatibility forms (full-width letters, ligatures) so "ｉｇｎｏｒｅ" and "ignore" look the same to the detectors.
* Zero-width / bidi-override / control characters are removed: they hide instructions from humans and split keywords.
* Common Cyrillic/Greek homoglyphs in otherwise-Latin words are folded ("аdmin" with a Cyrillic а -> "admin").
"""
import re
import unicodedata

MAX_LEN = 500

_INVISIBLE = re.compile("[​-‏‪-‮⁠-⁤⁦-⁩﻿­]")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_SPACES = re.compile(r"\s+")
_HOMOGLYPHS = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "һ": "h",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X",
    "α": "a", "ο": "o", "ν": "v", "ι": "i", "Α": "A", "Β": "B", "Ε": "E", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Τ": "T",
})


def sanitize(text: str, max_len: int = MAX_LEN) -> tuple[str, list[str]]:
    """Return (clean text, list of what was changed). Changes are audit signals, not errors."""
    flags: list[str] = []
    t = unicodedata.normalize("NFKC", text or "")
    if t != text:
        flags.append("unicode_normalised")
    t2 = _INVISIBLE.sub("", t)
    if t2 != t:
        flags.append("invisible_chars_removed")
    t3 = _CONTROL.sub(" ", t2)
    if t3 != t2:
        flags.append("control_chars_removed")
    t4 = t3.translate(_HOMOGLYPHS)
    if t4 != t3:
        flags.append("homoglyphs_folded")
    t5 = _SPACES.sub(" ", t4).strip()
    if len(t5) > max_len:
        t5 = t5[:max_len]
        flags.append("truncated")
    return t5, flags
