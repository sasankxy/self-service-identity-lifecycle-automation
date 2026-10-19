"""Intent evaluation: rules-only, Naive Bayes-only and hybrid on intent_test.json (+ negation handling).
python -m nlu.evaluation.evaluate_intent"""
import json

from ..config_loader import DEFAULT_DATA_DIR, DEFAULT_MODELS_DIR
from ..pipeline import NB_MODEL_NAME, NLUPipeline
from ..schemas import INTENTS
from .metrics import classification_report


def main():
    test = json.loads((DEFAULT_DATA_DIR / "intent_test.json").read_text())
    gold = [t["intent"] for t in test]
    out = {}
    for mode in ("rules_only", "nb_only", "hybrid"):
        # full pipeline NER (hybrid) so the rule classifier sees entity context
        p = NLUPipeline(ner_mode="hybrid", intent_mode=mode)
        pred = [p.parse(t["text"])["intent"]["label"] for t in test]
        rep = classification_report(gold, pred, INTENTS)
        neg_idx = [i for i, t in enumerate(test) if t.get("negated")]
        pos_idx = [i for i, t in enumerate(test) if not t.get("negated")]
        rep["negation_handling"] = {
            "n_negated": len(neg_idx),
            "correctly_not_triggering_action": round(sum(pred[i] == "UNKNOWN" for i in neg_idx) / len(neg_idx), 4),
            "non_negated_accuracy": round(sum(pred[i] == gold[i] for i in pos_idx) / len(pos_idx), 4)}
        out[mode] = rep
        print(f"\n== {mode}: accuracy={rep['accuracy']}  macro_f1={rep['macro_f1']}  (n={len(test)})")
        print("   negation:", rep["negation_handling"])
        for l, v in rep["per_class"].items():
            print(f"   {l:22s} P={v['precision']:.3f} R={v['recall']:.3f} F1={v['f1']:.3f} support={v['support']}")
        wrong = [(t["text"], g, q) for t, g, q in zip(test, gold, pred) if g != q][:6]
        for w in wrong:
            print("   ERR:", w)
    return out


if __name__ == "__main__":
    main()
