"""Deterministic generator for the synthetic NER / intent datasets.

Train and test use DISJOINT template sets, person names, unknown department/application names, typo
variants and reason phrases to reduce template leakage. Templates use a tiny markup:
  [text|TYPE]            literal annotated entity (e.g. [Move|ACTION])
  {P>slot} {D1>slot} ... placeholder filled from a pool and annotated; ">slot" records the gold slot.
Placeholders: P person, D department, A application, R access role, T date, W reason, E employee id.
Run:  python -m nlu.data.generate_datasets
"""
from __future__ import annotations

import json
import random
import re
from pathlib import Path

from ..config_loader import DEFAULT_DATA_DIR, load_configs
from ..preprocessing import preprocess
from ..ner import spans_to_bio

SEED = 20260415
REF = "2026-10-15"  # reference date (Thursday) for gold date values

PERSONS = {
    "train": ["Rahul Sharma", "Priya Nair", "Ananya Iyer", "Vikram Singh", "Meera Krishnan", "Arjun Mehta",
              "Sneha Patil", "John Smith", "Emily Clark", "Carlos Mendes", "Fatima Khan", "Li Wei", "Deepak Rao",
              "Kavya Reddy", "Rohan Gupta", "Neha Joshi", "Aditya Verma", "Sara Thomas", "Manoj Kumar",
              "Pooja Desai", "Rahul", "Priya", "Ananya", "Vikram", "Meera", "Arjun", "Sneha", "John", "Emily"]
             + [f"{a} {b}" for a, b in [("Kiran", "Kumar"), ("Nisha", "Das"), ("Varun", "Shah"), ("Anil", "Bose"), ("Shreya", "Ali"),
                                        ("Mohan", "Joshi"), ("Tara", "Brown"), ("Dev", "Taylor"), ("Zoya", "Wilson"), ("Ravi", "Rao"),
                                        ("Maya", "Singh"), ("Karan", "Mehra"), ("Leela", "Kulkarni"), ("Sanjay", "Gill"),
                                        ("Irfan", "Sheikh"), ("Jasmine", "Park"), ("Peter", "Moore"), ("Olivia", "Hart")]]
             + ["Kiran", "Nisha", "Varun", "Anil", "Shreya", "Mohan", "Tara", "Dev", "Zoya", "Ravi", "Maya", "Karan", "Leela"],
    "test": ["Suresh Menon", "Divya Bhat", "Harish Nambiar", "Isha Kapoor", "Tom Becker", "Aisha Rahman",
             "Nikhil Jain", "Lakshmi Pillai", "Omar Farouk", "Grace Liu", "Suresh", "Divya", "Isha", "Tom", "Aisha"],
}
UNKNOWN_DEPTS = {"train": ["Treasury", "Facilities", "Internal Audit", "Product Design", "Risk Management", "Brand Studio",
                           "Global Mobility", "Platform Services", "Customer Insights", "Security Operations"],
                 "test": ["Quantum Research", "Corporate Strategy", "Field Services"]}
UNKNOWN_APPS = {"train": ["Figma", "Zendesk", "Notion", "Asana", "Trello", "Postman", "Lucidchart", "Airtable"], "test": ["Snowflake", "Miro", "Datadog"]}
TYPO_DEPTS = {"train": [("Enginering", "Engineering"), ("Markting", "Marketing"), ("Finanse", "Finance")],
              "test": [("Enginnering", "Engineering"), ("Marketng", "Marketing"), ("Operatons", "Operations")]}
TYPO_APPS = {"train": [("Salesforse", "Salesforce"), ("Githb", "GitHub")],
             "test": [("Salesforec", "Salesforce"), ("Confluense", "Confluence")]}
REASONS = {"train": ["because of a team restructure", "due to a promotion", "because she accepted another offer",
                     "as part of the annual reorganisation", "due to a change in role",
                     "because of a project reassignment", "due to contract completion"],
           "test": ["because of a department merger", "due to relocation", "because he found a new job",
                    "as part of the audit cleanup", "due to end of internship"]}
# (prefix, surface, gold value | None, kind)   kind: ok | unresolved | ambiguous
DATES = {
    "train": [("", "tomorrow", "2026-10-16", "ok"), ("", "today", "2026-10-15", "ok"),
              ("", "next Monday", "2026-10-19", "ok"), ("", "this Friday", "2026-10-16", "ok"),
              ("", "at the end of the month", "2026-10-31", "ok"), ("", "in 3 days", "2026-10-18", "ok"),
              ("on ", "20 November", "2026-11-20", "ok"), ("", "next week", None, "unresolved"),
              ("", "at the end of next month", "2026-11-30", "ok"), ("", "2026-11-30", "2026-11-30", "ok"),
              ("on ", "15th December 2026", "2026-12-15", "ok"), ("on ", "Monday", "2026-10-19", "ok"),
              ("on ", "March 3", "2027-03-03", "ok"), ("", "in two weeks", "2026-10-29", "ok"),
              ("", "next Friday", None, "ambiguous"), ("by ", "Friday", "2026-10-16", "ok")],
    "test": [("", "tomorrow", "2026-10-16", "ok"), ("", "by the end of the quarter", "2026-12-31", "ok"),
             ("on ", "30/11/2026", "2026-11-30", "ok"), ("on ", "Nov 5", "2026-11-05", "ok"),
             ("", "in 5 days", "2026-10-20", "ok"), ("", "next Wednesday", "2026-10-21", "ok"),
             ("", "next month", None, "unresolved"), ("", "by the end of the year", "2026-12-31", "ok"),
             ("", "at the end of the week", None, "unresolved"), ("", "next Friday", None, "ambiguous"),
             ("", "this weekend", None, "unresolved")],
}
IDS = {"train": [("", "EMP4821", "EMP4821"), ("", "E-10293", "E10293"), ("employee ID ", "55821", "55821"),
                 ("", "EMP-7712", "EMP7712")],
       "test": [("", "EMP9034", "EMP9034"), ("", "E-20418", "E20418"), ("employee ID ", "30177", "30177")]}

# (intent, template, meta)   meta: self, neg (negated intent), unsup, pron
TEMPLATES = {"train": [
    ("JOINER", "{P>person} is [joining|ACTION] {D1>target_department} {T>effective_date}.", {}),
    ("JOINER", "Please [onboard|ACTION] the new hire {P>person} into {D1>target_department}.", {}),
    ("JOINER", "New joiner {P>person} will [join|ACTION] the {D1>target_department} team {T>effective_date}.", {}),
    ("JOINER", "[Onboard|ACTION] {P>person} in {D1>target_department}, starting {T>effective_date}.", {}),
    ("JOINER", "New hire {P>person} [joins|ACTION] {D1>target_department} and [needs access|ACTION] to {A1>applications} and {A2>applications}.", {}),
    ("JOINER", "Welcome {P>person} to {D1>target_department}! [Onboarding|ACTION] starts {T>effective_date}.", {}),
    ("JOINER", "[Onboard|ACTION] employee {E>employee_id} as a new hire in {D1>target_department} {W>reason}.", {}),
    ("JOINER", "{P>person} will be [joining|ACTION] the {D1>target_department} department {T>effective_date}.", {}),
    ("JOINER", "I am [joining|ACTION] {D1>target_department} {T>effective_date}.", {"self": True}),
    ("MOVER", "[Move|ACTION] {P>person} from {D1>source_department} to {D2>target_department}.", {}),
    ("MOVER", "[Transfer|ACTION] {P>person} to {D1>target_department} {T>effective_date}.", {}),
    ("MOVER", "{P>person} will [move to|ACTION] {D1>target_department} from {D2>source_department} {T>effective_date}.", {}),
    ("MOVER", "Please [transfer|ACTION] {P>person} out of {D1>source_department} and into {D2>target_department} {W>reason}.", {}),
    ("MOVER", "{P>person} is [moving to|ACTION] {D1>target_department} {W>reason}.", {}),
    ("MOVER", "[Move|ACTION] employee {E>employee_id} from {D1>source_department} to {D2>target_department} {T>effective_date}.", {}),
    ("MOVER", "I want to [move|ACTION] {P>person} to the {D1>target_department} team.", {}),
    ("MOVER", "{P>person} has been [transferred|ACTION] from the {D1>source_department} team to the {D2>target_department} team.", {}),
    ("MOVER", "I am [moving to|ACTION] {D1>target_department} {T>effective_date}.", {"self": True}),
    ("MOVER", "[Reassign|ACTION] {P>person} from {D1>source_department} to {D2>target_department}.", {}),
    ("LEAVER", "{P>person} is [leaving|ACTION] the company {T>effective_date}.", {}),
    ("LEAVER", "[Offboard|ACTION] {P>person} {T>effective_date}.", {}),
    ("LEAVER", "{P>person} from {D1>department} has [resigned|ACTION] {W>reason}.", {}),
    ("LEAVER", "Employee {E>employee_id} will [leave|ACTION] the company {T>effective_date}.", {}),
    ("LEAVER", "Please [terminate|ACTION] {P>person} in {D1>department} {T>effective_date}.", {}),
    ("LEAVER", "My last day is {T>effective_date}, I am [leaving|ACTION] the company.", {"self": True}),
    ("LEAVER", "{P>person} [resigned|ACTION] and is [leaving|ACTION] {D1>department}.", {}),
    ("LEAVER", "[Offboard|ACTION] {P>person} from {D1>department} {W>reason}.", {}),
    ("ACCESS_REQUEST", "[Give|ACTION] me access to {A1>applications}.", {"self": True}),
    ("ACCESS_REQUEST", "I [need access|ACTION] to {A1>applications} {W>reason}.", {"self": True}),
    ("ACCESS_REQUEST", "[Request access|ACTION] to {A1>applications} for {P>person}.", {}),
    ("ACCESS_REQUEST", "Please [grant|ACTION] {P>person} {R>access_roles} access to {A1>applications}.", {}),
    ("ACCESS_REQUEST", "Can I [get access|ACTION] to {A1>applications} and {A2>applications}?", {"self": True}),
    ("ACCESS_REQUEST", "{P>person} [needs access|ACTION] to {A1>applications} {T>effective_date}.", {}),
    ("ACCESS_REQUEST", "I would like to [request access|ACTION] to {A1>applications} as {R>access_roles}.", {"self": True}),
    ("ACCESS_REQUEST", "[Provision|ACTION] {R>access_roles} access on {A1>applications} for employee {E>employee_id}.", {}),
    ("ACCESS_REQUEST", "[Give|ACTION] {P>person} access to {A1>applications} {W>reason}.", {}),
    ("ACCESS_REQUEST", "Could you [grant|ACTION] me {R>access_roles} access in {A1>applications}?", {"self": True}),
    ("ACCESS_REVOCATION", "[Revoke|ACTION] {P>person}'s {A1>applications} access {T>effective_date}.", {}),
    ("ACCESS_REVOCATION", "[Remove access|ACTION] to {A1>applications} for {P>person}.", {}),
    ("ACCESS_REVOCATION", "Please [revoke|ACTION] my access to {A1>applications}.", {"self": True}),
    ("ACCESS_REVOCATION", "[Disable access|ACTION] to {A1>applications} for employee {E>employee_id} {W>reason}.", {}),
    ("ACCESS_REVOCATION", "{P>person} no longer needs {A1>applications}; [revoke|ACTION] {R>access_roles} access.", {}),
    ("ACCESS_REVOCATION", "[Deprovision|ACTION] {P>person} from {A1>applications} and {A2>applications} {T>effective_date}.", {}),
    ("ACCESS_REVOCATION", "I no longer [need access|ACTION] to {A1>applications}.", {"self": True}),
    ("ACCESS_REVOCATION", "Please [revoke|ACTION] the {R>access_roles} role from {P>person} on {A1>applications}.", {}),
    ("ACCESS_STATUS_QUERY", "Does {P>person} [have access|ACTION] to {A1>applications}?", {}),
    ("ACCESS_STATUS_QUERY", "Do I [have access|ACTION] to {A1>applications}?", {"self": True}),
    ("ACCESS_STATUS_QUERY", "What access does {P>person} have?", {}),
    ("ACCESS_STATUS_QUERY", "[Check access|ACTION] for {P>person} on {A1>applications}.", {}),
    ("ACCESS_STATUS_QUERY", "Has {P>person}'s {A1>applications} access been [granted|ACTION]?", {}),
    ("ACCESS_STATUS_QUERY", "What is the status of {P>person}'s {A1>applications} access request?", {}),
    ("ACCESS_STATUS_QUERY", "Which applications does {P>person} [have access|ACTION] to?", {}),
    ("ACCESS_STATUS_QUERY", "Show me all roles {P>person} has in {A1>applications}.", {}),
    # negation (label UNKNOWN, neg = the intent that would be wrongly triggered)
    ("UNKNOWN", "Do not [revoke|ACTION] {P>person}'s access to {A1}.", {"neg": "ACCESS_REVOCATION"}),
    ("UNKNOWN", "Please don't [remove access|ACTION] to {A1} for {P}.", {"neg": "ACCESS_REVOCATION"}),
    ("UNKNOWN", "Never [grant|ACTION] {P} {R} access to {A1}.", {"neg": "ACCESS_REQUEST"}),
    ("UNKNOWN", "{P} is not [leaving|ACTION] the company.", {"neg": "LEAVER"}),
    ("UNKNOWN", "Do not [move|ACTION] {P} to {D1}.", {"neg": "MOVER"}),
    ("UNKNOWN", "We are not [onboarding|ACTION] {P} {T}.", {"neg": "JOINER"}),
    ("UNKNOWN", "Cancel the request, do not [give|ACTION] {P} access to {A1}.", {"neg": "ACCESS_REQUEST"}),
    ("UNKNOWN", "No need to [revoke|ACTION] my access to {A1}.", {"neg": "ACCESS_REVOCATION", "self": True}),
    # unsupported / unknown
    ("UNKNOWN", "What is the weather in Bengaluru [today|EFFECTIVE_DATE]?", {"unsup": True}),
    ("UNKNOWN", "Reset my password for {A1}.", {"unsup": True}),
    ("UNKNOWN", "Book a meeting room for {T}.", {"unsup": True}),
    ("UNKNOWN", "I need a new laptop {T}.", {"unsup": True}),
    ("UNKNOWN", "{P} is on annual leave {T}.", {"unsup": True}),
    ("UNKNOWN", "Please update the salary for {P}.", {"unsup": True}),
    ("UNKNOWN", "Tell me a joke.", {"unsup": True}),
    ("UNKNOWN", "Hello there, thanks for your help.", {}),
    ("UNKNOWN", "What does the {D1} team do?", {}),
    # typos in verbs
    # generic wording variety (added after the first evaluation; different wording from the test templates)
    ("JOINER", "{P>person} has been hired and will [join|ACTION] {D1>target_department}.", {}),
    ("JOINER", "Please [onboard|ACTION] {P>person} to {D1>target_department} {T>effective_date}.", {}),
    ("JOINER", "{P>person} is a new hire, [joining|ACTION] the {D1>target_department} team.", {}),
    ("MOVER", "{P>person} gets [transferred|ACTION] to {D1>target_department}.", {}),
    ("MOVER", "{P>person} will be [transferred|ACTION] from {D1>source_department} to {D2>target_department}.", {}),
    ("MOVER", "{P>person} is [moving|ACTION] from {D1>source_department} to {D2>target_department} {T>effective_date}.", {}),
    ("LEAVER", "{P>person} will be [offboarded|ACTION] {T>effective_date}.", {}),
    ("LEAVER", "{P>person} has [resigned|ACTION] from {D1>department}.", {}),
    ("ACCESS_REQUEST", "{P>person} will [need access|ACTION] to {A1>applications}.", {}),
    ("ACCESS_STATUS_QUERY", "Has {P>person} got access to {A1>applications}?", {}),
    ("ACCESS_REVOCATION", "{P>person} has left, so [revoke|ACTION] their {A1>applications} access.", {}),
    ("ACCESS_REVOCATION", "[Revke|ACTION] {P>person}'s {A1>applications} acess {T>effective_date}.", {}),
    ("MOVER", "[Tranfer|ACTION] {P>person} to {D1>target_department} {W>reason}.", {}),
    ("JOINER", "[Onbaord|ACTION] {P>person} into {D1>target_department}.", {}),
], "test": [
    ("JOINER", "{P>person} starts in {D1>target_department} {T>effective_date}, please [onboard|ACTION] them.", {}),
    ("JOINER", "A new employee, {P>person}, [joins|ACTION] our {D1>target_department} team {T>effective_date}.", {}),
    ("JOINER", "Kindly [onboard|ACTION] {P>person} to {D1>target_department} {T>effective_date}.", {}),
    ("JOINER", "New hire alert: {P>person} is [joining|ACTION] {D1>target_department} {W>reason}.", {}),
    ("JOINER", "{P>person} will [join|ACTION] {D1>target_department} {T>effective_date} and [needs access|ACTION] to {A1>applications}.", {}),
    ("JOINER", "I'm [joining|ACTION] {D1>target_department} {T>effective_date} as a new hire.", {"self": True}),
    ("MOVER", "{P>person} is being [transferred|ACTION] to {D1>target_department} from {D2>source_department}.", {}),
    ("MOVER", "Kindly [move|ACTION] {P>person} out of {D1>source_department} into {D2>target_department} {T>effective_date}.", {}),
    ("MOVER", "{P>person} [moves to|ACTION] {D1>target_department} {T>effective_date} {W>reason}.", {}),
    ("MOVER", "[Reassign|ACTION] employee {E>employee_id} to {D1>target_department}.", {}),
    ("MOVER", "{P>person} is [leaving|ACTION] {D1>source_department} for {D2>target_department}.", {}),
    ("LEAVER", "{P>person} has [resigned|ACTION], last day is {T>effective_date}.", {}),
    ("LEAVER", "Kindly [offboard|ACTION] {P>person} from {D1>department} {T>effective_date}.", {}),
    ("LEAVER", "{P>person} will [leave|ACTION] the organisation {T>effective_date} {W>reason}.", {}),
    ("LEAVER", "Employee {E>employee_id} was [terminated|ACTION] {T>effective_date}.", {}),
    ("LEAVER", "I [resigned|ACTION] [today|EFFECTIVE_DATE], please [offboard|ACTION] me.", {"self": True, "fixed_date": ("today", "2026-10-15")}),
    ("ACCESS_REQUEST", "{P>person} [needs access|ACTION] to {A1>applications} as {R>access_roles}.", {}),
    ("ACCESS_REQUEST", "[Provision|ACTION] {A1>applications} access for {P>person} {T>effective_date}.", {}),
    ("ACCESS_REQUEST", "I would like {R>access_roles} access to {A1>applications} please.", {"self": True}),
    ("ACCESS_REQUEST", "Could you [give|ACTION] {P>person} access to {A1>applications} and {A2>applications}?", {}),
    ("ACCESS_REQUEST", "[Grant|ACTION] me {R>access_roles} access on {A1>applications} {W>reason}.", {"self": True}),
    ("ACCESS_REVOCATION", "[Revoke|ACTION] access to {A1>applications} for {P>person} {T>effective_date}.", {}),
    ("ACCESS_REVOCATION", "Please [remove access|ACTION] for {P>person} on {A1>applications} {W>reason}.", {}),
    ("ACCESS_REVOCATION", "[Deprovision|ACTION] employee {E>employee_id} from {A1>applications}.", {}),
    ("ACCESS_REVOCATION", "[Revoke|ACTION] my {R>access_roles} role in {A1>applications}.", {"self": True}),
    ("ACCESS_REVOCATION", "{P>person} should no longer have {A1>applications} access, please [revoke|ACTION] it {T>effective_date}.", {}),
    ("ACCESS_STATUS_QUERY", "Does {P>person} still [have access|ACTION] to {A1>applications}?", {}),
    ("ACCESS_STATUS_QUERY", "[Check access|ACTION] for employee {E>employee_id} in {A1>applications}.", {}),
    ("ACCESS_STATUS_QUERY", "What is the status of my {A1>applications} access request?", {"self": True}),
    ("ACCESS_STATUS_QUERY", "Has my access to {A1>applications} been [revoked|ACTION]?", {"self": True}),
    ("ACCESS_STATUS_QUERY", "Which roles does {P>person} have in {A1>applications}?", {}),
    ("UNKNOWN", "Don't [revoke|ACTION] access for {P} on {A1}.", {"neg": "ACCESS_REVOCATION"}),
    ("UNKNOWN", "{P} should not be [offboarded|ACTION] yet.", {"neg": "LEAVER"}),
    ("UNKNOWN", "Please avoid [granting|ACTION] {P} {R} access to {A1}.", {"neg": "ACCESS_REQUEST"}),
    ("UNKNOWN", "Do not [transfer|ACTION] {P} to {D1}.", {"neg": "MOVER"}),
    ("UNKNOWN", "Please renew my parking permit.", {"unsup": True}),
    ("UNKNOWN", "I need help with the [VPN|APPLICATION] client, it keeps failing.", {"unsup": False}),
    ("UNKNOWN", "Update the salary for {P}.", {"unsup": True}),
    ("UNKNOWN", "{P} is on sick leave {T}.", {"unsup": True}),
    ("UNKNOWN", "What time is the all-hands meeting?", {}),
    ("ACCESS_REVOCATION", "[Revoek|ACTION] {P>person}'s {A1>applications} access {T>effective_date}.", {}),
    ("MOVER", "[Transfr|ACTION] {P>person} to {D1>target_department}.", {}),
    ("LEAVER", "[Offbaord|ACTION] {P>person} {T>effective_date}.", {}),
]}


class Builder:
    def __init__(self, split, rng, ents_cfg):
        self.split, self.rng = split, rng
        self.known_depts = [(a, c) for c, s in ents_cfg["DEPARTMENT"].items() for a in [c] + s["aliases"]]
        self.known_apps = [(a, c) for c, s in ents_cfg["APPLICATION"].items() for a in [c] + s["aliases"]]
        self.roles = [(a, c) for c, s in ents_cfg["ACCESS_ROLE"].items() for a in [c] + s["aliases"]]

    def pick_known(self, pairs, typos, unknown):
        r = self.rng.random()
        if r < 0.10:
            s, c = self.rng.choice(typos[self.split]); return s, c, "typo"
        if r < 0.25:
            return self.rng.choice(unknown[self.split]), None, "unknown"
        s, c = self.rng.choice(pairs)
        return s, c, "known"

    def build(self, template, meta):
        """-> (text, entities, gold_slots, flags)"""
        rng, filled, cache, flags = self.rng, {}, {}, set()
        used_depts = set()
        gold = {"scalars": {}, "lists": {}}

        def expand(m):
            name, slot = m.group(1), m.group(2)
            key = m.group(0)
            kind = name[0]
            if name not in cache:
                if kind == "P":
                    cache[name] = (rng.choice(PERSONS[self.split]), "PERSON")
                elif kind == "D":
                    for _try in range(30):  # distinct departments within one sentence
                        cand = self.pick_known(self.known_depts, TYPO_DEPTS, UNKNOWN_DEPTS) + ("DEPARTMENT",)
                        ident = cand[1] or cand[0]
                        if ident not in used_depts:
                            break
                    used_depts.add(ident)
                    cache[name] = cand
                elif kind == "A":
                    cache[name] = self.pick_known(self.known_apps, TYPO_APPS, UNKNOWN_APPS) + ("APPLICATION",)
                elif kind == "R":
                    s, c = rng.choice(self.roles); cache[name] = (s, c, "known", "ACCESS_ROLE")
                elif kind == "T":
                    cache[name] = (rng.choice(DATES[self.split]), "EFFECTIVE_DATE")
                elif kind == "W":
                    cache[name] = (rng.choice(REASONS[self.split]), "REASON")
                elif kind == "E":
                    cache[name] = (rng.choice(IDS[self.split]), "EMPLOYEE_IDENTIFIER")
            v = cache[name]
            etype = v[-1]
            if etype == "PERSON":
                surface, canon = v[0], v[0]
            elif etype in ("DEPARTMENT", "APPLICATION", "ACCESS_ROLE"):
                surface, canon, how = v[0], v[1], v[2]
                if how == "unknown":
                    flags.add("unknown_department" if etype == "DEPARTMENT" else "unknown_application")
            elif etype == "EFFECTIVE_DATE":
                pre, surface, val, kind2 = v[0]
                canon = {"value": val, "expression": surface, "resolved": val is not None}
                if kind2 == "ambiguous":
                    flags.add("ambiguous_date")
                if pre:
                    return pre + f"[{surface}|{etype}|{slot or ''}]"
            elif etype == "REASON":
                surface, canon = v[0], v[0]
            else:  # employee id
                pre, surface, canon = v[0]
                if pre:
                    return pre + f"[{surface}|{etype}|{slot or ''}]"
            cache[key] = canon
            return f"[{surface}|{etype}|{slot or ''}]"

        # remember canonical values per placeholder occurrence
        values = {}

        def expand2(m):
            out = expand(m)
            slot = m.group(2)
            name = m.group(1)
            v = cache[name]
            etype = v[-1]
            if slot:
                if etype == "PERSON":
                    canon = v[0]
                elif etype in ("DEPARTMENT", "APPLICATION", "ACCESS_ROLE"):
                    canon = v[1]
                elif etype == "EFFECTIVE_DATE":
                    pre, surface, val, _ = v[0]
                    canon = {"value": val, "expression": surface, "resolved": val is not None}
                elif etype == "REASON":
                    canon = v[0]
                else:
                    canon = v[0][2]
                values[len(values)] = (slot, canon, etype)
            return out

        marked = re.sub(r"\{(\w+)(?:>(\w+))?\}", expand2, template)
        # parse markup into text + spans
        text, spans, pos, order = "", [], 0, []
        for m in re.finditer(r"\[([^\[\]|]+)\|([A-Z_]+)(?:\|(\w*))?\]", marked):
            text += marked[pos:m.start()]
            s = len(text)
            text += m.group(1)
            spans.append({"start": s, "end": len(text), "type": m.group(2)})
            pos = m.end()
        text += marked[pos:]
        # slot gold in placeholder order
        for slot, canon, etype in values.values():
            if slot in ("applications", "access_roles"):
                gold["lists"].setdefault(slot, [])
                if canon and canon not in gold["lists"][slot]:
                    gold["lists"][slot].append(canon)
            else:
                gold["scalars"][slot] = canon
        return text, spans, gold, flags


def expected_for(intent, meta, gold, flags, SLOT_SCHEMAS, REQUIRED):
    slots = {}
    for k in SLOT_SCHEMAS[intent]:
        slots[k] = [] if k in ("applications", "access_roles") else None
    if intent == "UNKNOWN":
        return {}, [], sorted(flags | ({"negated_action"} if meta.get("neg") else set())), "UNKNOWN_INTENT"
    for k, v in gold["scalars"].items():
        if k in slots:
            slots[k] = v
    for k, v in gold["lists"].items():
        if k in slots:
            slots[k] = v
    if meta.get("self") and not slots.get("person") and not slots.get("employee_id"):
        slots["subject_reference"] = "SELF"
    missing = []
    for r in REQUIRED[intent]:
        ok = (slots.get("person") or slots.get("employee_id") or slots.get("subject_reference")) if r == "person" else slots.get(r)
        if not ok:
            missing.append(r)
    blocking = sorted(f for f in flags)
    status = "NEEDS_CLARIFICATION" if (missing or blocking) else "PARSED"
    return slots, missing, blocking, status


def make_split(split, n_per_template, ents_cfg, seed):
    from ..schemas import SLOT_SCHEMAS, REQUIRED_SLOTS
    rng = random.Random(seed)
    b = Builder(split, rng, ents_cfg)
    ner, intent, pipe, seen = [], [], [], set()
    for intent_label, tpl, meta in TEMPLATES[split]:
        made = 0
        for _ in range(n_per_template * 6):
            if made >= n_per_template:
                break
            text, spans, gold, flags = b.build(tpl, meta)
            if text in seen:
                continue
            seen.add(text)
            made += 1
            doc = preprocess(text)
            bio = spans_to_bio(doc, spans)
            ner.append({"text": text, "entities": spans, "tokens": [t.text for t in doc.tokens], "bio": bio})
            row = {"text": text, "intent": intent_label}
            if meta.get("neg"):
                row["negated"] = True
            intent.append(row)
            slots, missing, blocking, status = expected_for(intent_label, meta, gold, flags, SLOT_SCHEMAS, REQUIRED_SLOTS)
            if intent_label == "UNKNOWN" and meta.get("unsup"):
                blocking = sorted(set(blocking) | {"unsupported_request"})
            elif intent_label == "UNKNOWN" and not meta.get("neg"):
                blocking = sorted(set(blocking) | {"unknown_intent"})
            pipe.append({"text": text, "intent": intent_label, "slots": slots, "missing_fields": missing,
                         "blocking_ambiguities": blocking, "status": status, "negated": bool(meta.get("neg"))})
    return ner, intent, pipe


def main():
    ents_cfg, _ = load_configs()
    out = DEFAULT_DATA_DIR
    tr_ner, tr_int, tr_pipe = make_split("train", 9, ents_cfg, SEED)
    te_ner, te_int, te_pipe = make_split("test", 8, ents_cfg, SEED + 1)
    dump = lambda name, obj: (out / name).write_text(json.dumps(obj, indent=1, ensure_ascii=False))
    dump("ner_train.json", tr_ner); dump("ner_test.json", te_ner)
    dump("intent_train.json", tr_int); dump("intent_test.json", te_int)
    dump("pipeline_generated_test.json", te_pipe)
    print(f"ner train/test: {len(tr_ner)}/{len(te_ner)}  intent train/test: {len(tr_int)}/{len(te_int)}  pipeline_generated_test: {len(te_pipe)}")


if __name__ == "__main__":
    main()
