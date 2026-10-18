"""Small hand-written metrics (no sklearn dependency)."""
from collections import Counter, defaultdict
from typing import Dict, Iterable, List, Sequence, Set, Tuple


def prf(tp: int, fp: int, fn: int) -> Dict[str, float]:
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return {"precision": round(p, 4), "recall": round(r, 4), "f1": round(f, 4), "tp": tp, "fp": fp, "fn": fn}


def entity_prf(gold: Sequence[Set[Tuple]], pred: Sequence[Set[Tuple]]) -> Dict[str, dict]:
    """Entity-level exact match on (start, end, type); micro overall + per type."""
    c = defaultdict(lambda: [0, 0, 0])
    for g, p in zip(gold, pred):
        for e in g & p:
            c[e[2]][0] += 1
        for e in p - g:
            c[e[2]][1] += 1
        for e in g - p:
            c[e[2]][2] += 1
    out = {t: prf(*v) for t, v in sorted(c.items())}
    tp, fp, fn = (sum(v[i] for v in c.values()) for i in range(3))
    out["MICRO"] = prf(tp, fp, fn)
    out["MACRO_F1"] = round(sum(v["f1"] for k, v in out.items() if k != "MICRO") / max(1, len(out) - 1), 4)
    return out


def classification_report(gold: List[str], pred: List[str], labels: Iterable[str]) -> dict:
    labels = list(labels)
    per = {}
    for l in labels:
        tp = sum(1 for g, p in zip(gold, pred) if g == l and p == l)
        fp = sum(1 for g, p in zip(gold, pred) if g != l and p == l)
        fn = sum(1 for g, p in zip(gold, pred) if g == l and p != l)
        per[l] = prf(tp, fp, fn)
        per[l]["support"] = sum(1 for g in gold if g == l)
    present = [l for l in labels if per[l]["support"] > 0]
    return {"accuracy": round(sum(g == p for g, p in zip(gold, pred)) / len(gold), 4),
            "macro_f1": round(sum(per[l]["f1"] for l in present) / len(present), 4), "per_class": per}
