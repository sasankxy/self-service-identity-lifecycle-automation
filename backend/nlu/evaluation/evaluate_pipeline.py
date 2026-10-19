"""End-to-end evaluation: intent, slot-filling exact match, negation handling, ambiguity detection.
python -m nlu.evaluation.evaluate_pipeline [--show-failures]"""
import argparse
import json
from datetime import date

from ..config_loader import DEFAULT_DATA_DIR
from ..pipeline import NLUPipeline
from ..schemas import LIST_SLOTS, SLOT_SCHEMAS
from .metrics import prf

REF = date(2026, 10, 15)


def full_gold_slots(intent, slots):
    base = {k: ([] if k in LIST_SLOTS else None) for k in SLOT_SCHEMAS[intent]}
    base.update(slots)
    return base


def evaluate(cases, pipe, show=False, title=""):
    n = len(cases)
    intent_ok = slot_ok = slot_n = status_ok = amb_exact = 0
    neg_n = neg_ok = 0
    tp = fp = fn = 0
    pos_pred = pos_gold = pos_both = 0
    fails = []
    for c in cases:
        r = pipe.parse(c["text"])
        gi = c["intent"] if isinstance(c["intent"], list) else [c["intent"]]
        pi = r["intent"]["label"]
        ok_i = pi in gi
        intent_ok += ok_i
        if c.get("slots") is not None:
            slot_n += 1
            gold = full_gold_slots(gi[0], c["slots"])
            good = ok_i and r["slots"] == gold and sorted(r["missing_fields"]) == sorted(c["missing_fields"])
            slot_ok += good
            if not good:
                fails.append((c["text"], "slots", gold, r["slots"], c["missing_fields"], r["missing_fields"]))
        pred_amb = {a["type"] for a in r["ambiguities"] if a["blocking"]}
        gold_amb = set(c["blocking_ambiguities"])
        tp += len(pred_amb & gold_amb); fp += len(pred_amb - gold_amb); fn += len(gold_amb - pred_amb)
        amb_exact += pred_amb == gold_amb
        if pred_amb != gold_amb:
            fails.append((c["text"], "ambiguities", sorted(gold_amb), sorted(pred_amb)))
        status_ok += r["status"] == c["status"]
        gp, pp = c["status"] != "PARSED", r["status"] != "PARSED"
        pos_gold += gp; pos_pred += pp; pos_both += gp and pp
        if c.get("negated"):
            neg_n += 1
            neg_ok += ok_i and bool(pred_amb & {"negated_action", "mixed_negation"})
        if not ok_i:
            fails.append((c["text"], "intent", gi, pi))
    res = {"n": n, "intent_accuracy": round(intent_ok / n, 4),
           "slot_filling_exact_match": round(slot_ok / slot_n, 4) if slot_n else None, "slot_cases": slot_n,
           "status_accuracy": round(status_ok / n, 4),
           "negation_handling": {"n": neg_n, "correct_intent_and_negation_flagged": round(neg_ok / neg_n, 4) if neg_n else None},
           "ambiguity_detection": {"blocking_type_prf": prf(tp, fp, fn), "case_level_exact_set_match": round(amb_exact / n, 4),
                                   "needs_clarification_detection": prf(pos_both, pos_pred - pos_both, pos_gold - pos_both)}}
    print(f"\n===== {title} (n={n}) =====")
    print(json.dumps(res, indent=1))
    if show:
        for f in fails:
            print(" FAIL", f)
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--show-failures", action="store_true")
    a = ap.parse_args()
    pipe = NLUPipeline(reference_date=REF)
    hand = json.loads((DEFAULT_DATA_DIR / "pipeline_test.json").read_text())
    gen = json.loads((DEFAULT_DATA_DIR / "pipeline_generated_test.json").read_text())
    evaluate(hand, pipe, a.show_failures, "hand-written end-to-end gold")
    evaluate(gen, pipe, a.show_failures, "template-generated held-out test")


if __name__ == "__main__":
    main()
