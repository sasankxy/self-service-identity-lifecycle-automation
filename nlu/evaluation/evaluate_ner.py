"""Entity-level evaluation of rules-only, CRF-only and hybrid NER on ner_test.json.
python -m nlu.evaluation.evaluate_ner [--errors N]"""
import argparse
import json

from ..config_loader import DEFAULT_DATA_DIR, DEFAULT_MODELS_DIR, load_configs
from ..features import Lexicons
from ..ner import CRFNER, HybridNER, RuleBasedNER
from ..pipeline import CRF_MODEL_NAME
from ..preprocessing import preprocess
from .metrics import entity_prf


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--errors", type=int, default=0, help="print N example errors for the hybrid system")
    args = ap.parse_args()
    ents, pats = load_configs()
    test = json.loads((DEFAULT_DATA_DIR / "ner_test.json").read_text())
    crf = CRFNER(Lexicons(ents, pats), pats["typo_lexicon"]).load(DEFAULT_MODELS_DIR / CRF_MODEL_NAME)
    rules = RuleBasedNER(ents, pats)
    gold = [{(e["start"], e["end"], e["type"]) for e in ex["entities"]} for ex in test]
    results, hybrid_pred = {}, None
    for mode in ("rules_only", "crf_only", "hybrid"):
        ner = HybridNER(rules, crf, mode)
        preds = []
        for ex in test:
            es, _ = ner.extract(preprocess(ex["text"], pats["typo_lexicon"]))
            preds.append({(e.start, e.end, e.type) for e in es})
        results[mode] = entity_prf(gold, preds)
        if mode == "hybrid":
            hybrid_pred = preds
    print(f"test sentences: {len(test)}, gold entities: {sum(len(g) for g in gold)}")
    types = [t for t in results["hybrid"] if t not in ("MICRO", "MACRO_F1")]
    print(f"{'type':22s}" + "".join(f"{m:>26s}" for m in results))
    print(f"{'':22s}" + "".join(f"{'P / R / F1':>26s}" for _ in results))
    for t in types + ["MICRO"]:
        row = f"{t:22s}"
        for m in results:
            r = results[m].get(t)
            row += f"{(f'{r['precision']:.3f} / {r['recall']:.3f} / {r['f1']:.3f}' if r else '-'):>26s}"
        print(row)
    print("macro-F1: " + ", ".join(f"{m}={results[m]['MACRO_F1']}" for m in results))
    if args.errors:
        n = 0
        for ex, g, p in zip(test, gold, hybrid_pred):
            if g != p and n < args.errors:
                n += 1
                f = lambda s: sorted((ex['text'][a:b], t) for a, b, t in s)
                print("\nTEXT:", ex["text"], "\n  missed:", f(g - p), "\n  spurious:", f(p - g))
    return results


if __name__ == "__main__":
    main()
