"""Thin wrapper around the standalone `nlu` package (rules + CRF + Naive Bayes).

* The pipeline is loaded once, lazily, and shared (it is read-only after loading).
* parse() is CPU-bound and synchronous, so it runs in a worker thread and never blocks the event loop.
* If the NLU package or its models cannot be loaded, `parse()` returns None and the assistant falls back to
  its original keyword rules. A broken model file must never take the assistant down.
* The NLU package ships static dictionaries. At startup `configure()` replaces them with the directory's real
  departments, applications and entitlement names (plus the aliases below), so extracted entities are already
  canonical database values and need no translation.
"""
from __future__ import annotations

import logging
import threading
from datetime import date

from starlette.concurrency import run_in_threadpool

log = logging.getLogger("identityos.nlu")

_pipeline = None
_failed = False
_catalogue: dict | None = None      # {'departments': [...], 'applications': [...], 'entitlements': [...]}
_lock = threading.Lock()


def _load():
    global _pipeline, _failed
    if _pipeline is not None or _failed:
        return _pipeline
    with _lock:
        if _pipeline is None and not _failed:
            try:
                from nlu import NLUPipeline  # backend/nlu (copied from nlu_pipeline.zip)
                _pipeline = NLUPipeline(entities_cfg=merged_entities(_catalogue) if _catalogue else None)
                log.info("NLU pipeline loaded (ner=%s intent=%s)", _pipeline.ner_mode, _pipeline.intent_mode)
            except Exception:  # noqa: BLE001 - missing sklearn-crfsuite, missing model file, ...
                _failed = True
                log.exception("NLU pipeline unavailable; assistant will use keyword rules only")
    return _pipeline


def configure(catalogue: dict | None) -> None:
    """Install the directory catalogue and drop any previously built pipeline."""
    global _catalogue, _pipeline, _failed
    with _lock:
        _catalogue, _pipeline, _failed = catalogue, None, False


def catalogue() -> dict:
    return _catalogue or {"departments": [], "applications": [], "entitlements": []}


def warm_up() -> bool:
    """Call at startup so the first user request does not pay the model-load cost."""
    return _load() is not None


def _parse_sync(text: str, ref: date | None) -> dict | None:
    p = _load()
    if p is None:
        return None
    try:
        return p.parse(text, reference_date=ref)
    except Exception:  # noqa: BLE001
        log.exception("NLU parse failed")
        return None


async def parse(text: str, reference_date: date | None = None) -> dict | None:
    return await run_in_threadpool(_parse_sync, text, reference_date)


# ---------------------------------------------------------------- directory vocabulary
# Aliases people actually type -> directory name. Anything not listed is matched by its own name only.
DEPT_ALIASES: dict[str, list[str]] = {
    "Engineering": ["Eng", "Software Engineering"], "Finance": ["Fin"], "Marketing": ["Mktg"], "Operations": ["Ops"],
    "Human Resources": ["HR", "People Ops", "People Operations"],
    "Support": ["Customer Support", "Customer Service", "CS"],
    "IT Security": ["IT Support", "IT", "Helpdesk", "Help Desk", "IT Helpdesk", "InfoSec", "Information Security"],  # ASSUMPTION
    "Product Design": ["Design", "Product Designers"],
}
APP_ALIASES: dict[str, list[str]] = {
    "ERP": ["SAP", "SAP ERP"],                                                   # ASSUMPTION: SAP is the directory's ERP
    "Microsoft 365": ["Office 365", "O365", "M365", "Microsoft Office 365"], "AWS": ["AWS Console", "Amazon Web Services"],
    "Network": ["VPN", "Corporate VPN"], "Google": ["Google Workspace", "GSuite"], "GitHub": ["Git Hub", "GH"],
    "ServiceNow": ["Service Now", "SNOW"], "Salesforce": ["SFDC", "Sales Force"],
}


def merged_entities(cat: dict, base: dict | None = None) -> dict:
    """Entity dictionaries for the NLU built from the directory: canonical names are DB values."""
    import json
    from copy import deepcopy
    from pathlib import Path
    if base is None:
        import nlu as _pkg
        base = json.loads((Path(_pkg.__file__).parent / "config" / "entities.json").read_text(encoding="utf-8"))
    cfg = deepcopy(base)
    old_d, old_a = base["DEPARTMENT"], base["APPLICATION"]
    cfg["DEPARTMENT"] = {n: {"aliases": sorted(set(DEPT_ALIASES.get(n, [])) | set(old_d.get(n, {}).get("aliases", [])))}
                         for n in cat["departments"]}
    cfg["APPLICATION"] = {n: {"aliases": sorted(set(APP_ALIASES.get(n, [])) | set(old_a.get(n, {}).get("aliases", [])))}
                          for n in cat["applications"]}
    taken = {x.lower() for sect in ("DEPARTMENT", "APPLICATION") for n, v in cfg[sect].items() for x in [n, *v["aliases"]]}
    # entitlement names ("AP Payment Release") are the directory's roles; skip ones that are also an application name
    cfg["ACCESS_ROLE"] = {n: {"aliases": []} for n in cat.get("entitlements", []) if n.lower() not in taken}
    return cfg


async def load_catalogue(db) -> dict:
    from sqlalchemy import select
    from app.models import Department, Entitlement
    d = (await db.execute(select(Department.name).order_by(Department.name))).scalars().all()
    a = (await db.execute(select(Entitlement.application).distinct().order_by(Entitlement.application))).scalars().all()
    e = (await db.execute(select(Entitlement.name).order_by(Entitlement.name))).scalars().all()
    return {"departments": list(d), "applications": list(a), "entitlements": list(e)}


ASSISTANT_INTENTS = {"JOINER", "MOVER", "LEAVER", "ACCESS_REQUEST", "ACCESS_REVOCATION", "ACCESS_STATUS_QUERY"}
SELF_OK = {"ACCESS_STATUS_QUERY", "ACCESS_REQUEST", "ACCESS_REVOCATION"}


def in_directory(kind: str, name: str | None) -> bool:
    return bool(name) and name.lower() in {x.lower() for x in catalogue().get(kind, [])}


def is_actionable(res: dict | None) -> bool:
    """True when the NLU found a lifecycle intent AND something concrete to look up (a person / employee id /
    'me'). Everything else (e.g. 'show pending approvals', which this NLU mislabels as a status query) is left
    to the assistant's original keyword rules, so existing behaviour does not regress."""
    if not res or res["status"] == "UNKNOWN_INTENT":
        return False
    label = res["intent"]["label"]
    if label not in ASSISTANT_INTENTS:
        return False
    s = res["slots"]
    if s.get("person") or s.get("employee_id"):
        return True
    return s.get("subject_reference") == "SELF" and label in SELF_OK
