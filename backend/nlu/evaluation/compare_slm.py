"""Custom NLU engine vs a local SLM (Ollama) on the hand-written end-to-end gold set.

    ollama pull qwen2.5:3b
    python -m nlu.evaluation.compare_slm --model qwen2.5:3b [--url http://localhost:11434] [--show-failures]
    python -m nlu.evaluation.compare_slm --dry-run            # no Ollama: checks the metric code with the custom engine standing in

Compared on what both can produce: intent, and entity values for person / source_department / target_department /
applications (entity-level micro precision / recall / F1). Dates are excluded because the SLM is never asked for them
(the date engine is deterministic by design). Also reported: median latency per request, and the SLM's *hallucination
rate* = predicted departments/applications that are not in the catalogue (the production code discards those).
"""
from __future__ import annotations

import argparse
import json
import statistics
import time
import urllib.request
from datetime import date

from ..config_loader import DEFAULT_DATA_DIR, load_configs
from ..pipeline import NLUPipeline
from .metrics import prf

FIELDS = ("person", "source_department", "target_department", "applications")
INTENTS = ["JOINER", "MOVER", "LEAVER", "ACCESS_REQUEST", "ACCESS_REVOCATION", "ACCESS_STATUS_QUERY", "UNKNOWN"]
SCHEMA = {"type": "object", "properties": {
    "intent": {"type": "string", "enum": INTENTS}, "person": {"type": ["string", "null"]},
    "source_department": {"type": ["string", "null"]}, "target_department": {"type": ["string", "null"]},
    "applications": {"type": "array", "items": {"type": "string"}}},
    "required": ["intent", "person", "source_department", "target_department", "applications"]}


def prompt(depts, apps):      # mirrors app/services/slm.py so the experiment tests what production would run
    return ("You interpret identity-lifecycle requests for an IT access-management system. Reply with JSON only.\n"
            f"Allowed departments: {', '.join(depts)}.\nAllowed applications: {', '.join(apps)}.\n"
            "Choose departments/applications ONLY from the allowed lists, otherwise null / empty list. Copy the person's name exactly or null. "
            "Intents: JOINER (new hire), MOVER (change department), LEAVER (offboarding), ACCESS_REQUEST (wants access), "
            "ACCESS_REVOCATION (remove access), ACCESS_STATUS_QUERY (asks what access exists), UNKNOWN.")


def ollama(url, model, depts, apps):
    def call(text):
        body = json.dumps({"model": model, "stream": False, "format": SCHEMA, "options": {"temperature": 0},
                           "messages": [{"role": "system", "content": prompt(depts, apps)}, {"role": "user", "content": text}]}).encode()
        req = urllib.request.Request(f"{url}/api/chat", body, {"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=120) as r:
            return json.loads(json.loads(r.read())["message"]["content"])
    return call


def custom(pipe):
    def call(text):
        r = pipe.parse(text)
        s = r["slots"]
        return {"intent": r["intent"]["label"], "person": s.get("person"), "source_department": s.get("source_department"),
                "target_department": s.get("target_department"), "applications": s.get("applications") or []}
    return call


def entities(d: dict) -> set:
    out = set()
    for f in FIELDS:
        v = d.get(f)
        for x in (v if isinstance(v, list) else [v] if v else []):
            if isinstance(x, str) and x.strip():
                out.add((f, x.strip().lower()))
    return out


def run(name, call, cases, catalogue, show=False):
    tp = fp = fn = intent_ok = bad = produced = 0
    lat, fails = [], []
    for c in cases:
        t0 = time.perf_counter()
        try:
            out = call(c["text"])
        except Exception as e:  # noqa: BLE001
            out, fails = {"intent": "ERROR"}, fails + [(c["text"], f"error: {e}")]
        lat.append(time.perf_counter() - t0)
        gi = c["intent"] if isinstance(c["intent"], list) else [c["intent"]]
        intent_ok += out.get("intent") in gi
        gold, pred = entities({k: c.get("slots", {}).get(k) for k in FIELDS}), entities(out)
        tp += len(gold & pred); fp += len(pred - gold); fn += len(gold - pred)
        for f, v in pred:
            if f in ("source_department", "target_department", "applications"):
                produced += 1
                bad += v not in catalogue
        if show and (gold != pred or out.get("intent") not in gi):
            fails.append((c["text"], sorted(gold), sorted(pred), out.get("intent"), gi))
    n = len(cases)
    res = {"engine": name, "n": n, "intent_accuracy": round(intent_ok / n, 4), "entity": prf(tp, fp, fn),
           "median_latency_s": round(statistics.median(lat), 4), "hallucination_rate": round(bad / produced, 4) if produced else 0.0}
    print(json.dumps(res, indent=1))
    for f in fails:
        print("  FAIL", f)
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="qwen2.5:3b"); ap.add_argument("--url", default="http://localhost:11434")
    ap.add_argument("--show-failures", action="store_true"); ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    ents, _ = load_configs()
    depts, apps = list(ents["DEPARTMENT"]), list(ents["APPLICATION"])
    catalogue = {x.lower() for x in depts + apps}
    cases = json.loads((DEFAULT_DATA_DIR / "pipeline_test.json").read_text())
    cases = [c for c in cases if c.get("slots") is not None]
    pipe = NLUPipeline(reference_date=date(2026, 10, 15))
    out = [run("custom NLU engine", custom(pipe), cases, catalogue, a.show_failures)]
    out.append(run("dry-run stand-in" if a.dry_run else f"SLM {a.model}", custom(pipe) if a.dry_run else ollama(a.url, a.model, depts, apps),
                   cases, catalogue, a.show_failures))
    print("\nDelta (SLM - custom): intent %+.4f  entity F1 %+.4f" % (out[1]["intent_accuracy"] - out[0]["intent_accuracy"],
                                                                  out[1]["entity"]["f1"] - out[0]["entity"]["f1"]))


if __name__ == "__main__":
    main()
