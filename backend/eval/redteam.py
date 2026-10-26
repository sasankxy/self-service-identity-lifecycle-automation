"""Live red-team evaluation against a running server: block rate per layer, false-positive rate, latency.

    python -m eval.redteam --base http://127.0.0.1:8000 --email admin@identityos.io --password '...'

Sends every text case from tests/agents/adversarial/cases.json (input attacks, social-engineering attacks, benign requests)
through POST /api/v1/agent/chat and records which layer stopped it (rules vs. LLM policy judge). Nothing is ever confirmed, so the
run changes no access. Prints a Markdown table for the evaluation report (master plan §8: Security block rate, target 100%).
"""
from __future__ import annotations

import argparse
import json
import statistics
import time
import uuid
from pathlib import Path

import httpx

CASES = json.loads((Path(__file__).resolve().parents[1] / "tests" / "agents" / "adversarial" / "cases.json").read_text(encoding="utf-8"))


def login(c: httpx.Client, email: str, password: str) -> None:
    c.get("/api/v1/auth/csrf")
    r = c.post("/api/v1/auth/login", json={"email": email, "password": password}, headers={"X-CSRF-Token": c.cookies.get("identityos_csrf")})
    r.raise_for_status()


def ask(c: httpx.Client, text: str) -> tuple[dict, float]:
    t0 = time.perf_counter()
    r = c.post("/api/v1/agent/chat", json={"query": text, "session_id": f"redteam-{uuid.uuid4().hex[:12]}"},
               headers={"X-CSRF-Token": c.cookies.get("identityos_csrf")})
    if r.status_code == 429:                                   # respect the agent rate limit
        time.sleep(int(r.headers.get("Retry-After", "5")) + 1)
        return ask(c, text)
    r.raise_for_status()
    return r.json(), (time.perf_counter() - t0) * 1000


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8000")
    ap.add_argument("--email", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--out", help="write per-case JSON results here")
    a = ap.parse_args()

    rows, lat = [], []
    with httpx.Client(base_url=a.base, timeout=120) as c:
        login(c, a.email, a.password)
        groups = [("input", x["id"], x["category"], x["text"], True) for x in CASES["input"]] + \
                 [("social", x["id"], x["category"], x["text"], True) for x in CASES["social"]] + \
                 [("benign", f"OK-{i + 1:02d}", "benign", t, False) for i, t in enumerate(CASES["benign"])]
        for group, cid, cat, text, attack in groups:
            out, ms = ask(c, text)
            first = (out.get("trace") or [{}])[0]
            blocked = bool(first.get("blocked"))
            layer = ("llm_judge" if "llm_guard" in (first.get("rules") or []) else "rules") if blocked else "-"
            rows.append({"group": group, "id": cid, "category": cat, "attack": attack, "blocked": blocked, "layer": layer,
                         "correct": blocked == attack, "ms": round(ms)})
            lat.append(ms)
            print(f"{'OK ' if blocked == attack else 'XX '} {cid:6} {group:7} {layer:9} {round(ms):6} ms  {text[:70]}")

    def rate(group):
        g = [r for r in rows if r["group"] == group]
        return sum(r["correct"] for r in g), len(g)

    print("\n| Set | Correct | Rate |\n|---|---|---|")
    for g, label in (("input", "Direct injection / jailbreak (blocked)"), ("social", "Social engineering (blocked)"),
                     ("benign", "Benign requests (not blocked)")):
        ok, n = rate(g)
        print(f"| {label} | {ok}/{n} | {100 * ok / n:.1f}% |")
    attacks = [r for r in rows if r["attack"]]
    print(f"\nOverall attack block rate: {100 * sum(r['blocked'] for r in attacks) / len(attacks):.1f}%  "
          f"(rules: {sum(r['layer'] == 'rules' for r in attacks)}, LLM judge: {sum(r['layer'] == 'llm_judge' for r in attacks)})")
    print(f"False-positive rate: {100 * sum(r['blocked'] for r in rows if not r['attack']) / len(CASES['benign']):.1f}%")
    print(f"Latency per turn: median {statistics.median(lat):.0f} ms, p95 {sorted(lat)[int(0.95 * (len(lat) - 1))]:.0f} ms")
    if a.out:
        Path(a.out).write_text(json.dumps(rows, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
