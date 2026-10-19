# Identity Lifecycle NLU Pipeline

A standalone, modular Natural Language Understanding library for self-service identity lifecycle requests
(joiner / mover / leaver / access request / access revocation / access status query).
It takes a string and returns a JSON-compatible `dict`. **No** agent, LLM/SLM, external inference API, backend
framework, database, auth or UI code is included or imported.

```python
from nlu import NLUPipeline
nlu = NLUPipeline()                       # hybrid NER (rules + CRF) and hybrid intent (rules + Naive Bayes)
result = nlu.parse("Move Rahul Sharma from Engineering to Finance.")
```

## Setup

```bash
pip install -r nlu/requirements.txt          # sklearn-crfsuite (+ pytest for tests)
python -m nlu.data.generate_datasets          # (optional) regenerate synthetic data, seed fixed
python -m nlu.training.train_ner              # trains CRF -> nlu/models/ner_crf.crfsuite
python -m nlu.training.train_intent           # trains TF-IDF + NB -> nlu/models/intent_nb.json
python -m nlu.evaluation.evaluate_ner --errors 5
python -m nlu.evaluation.evaluate_intent
python -m nlu.evaluation.evaluate_pipeline --show-failures
python -m pytest nlu/tests -q
```
Trained model files are included in `nlu/models/`. Run all commands from the directory that contains `nlu/`.
Python 3.9+ (developed/tested on 3.12 with sklearn-crfsuite 0.5.0 / python-crfsuite 0.9.12).

If `sklearn-crfsuite` is missing, `NLUPipeline()` raises `MissingDependencyError`; if a model file is missing it
raises `ModelNotTrainedError`. **Nothing is silently substituted.** For a deliberately rule-only pipeline pass
`ner_mode="rules_only", intent_mode="rules_only"` (reported in `meta`; PERSON is then not extracted, because
person names are only found by the CRF).

## Architecture

| Module | Responsibility |
|---|---|
| `preprocessing.py` | Offset-preserving regex tokenizer (possessive `'s` split), closed-lexicon typo correction (sets `Token.corr`, never alters spans), negation-window helper |
| `features.py` | Hand-written CRF token features: lower-case form, capitalisation/shape, 1-4 char prefixes/suffixes, digit/hyphen flags, +/-2 token window, bigrams, config-derived lexicon categories (dept/app/role/action/month/weekday/cue words), possessive-next cue |
| `ner.py` | `RuleBasedNER`, `CRFNER` (train / predict / persist, BIO), `HybridNER` (conflict resolution) |
| `intent_classifier.py` | Rule baseline with evidence; custom TF-IDF + multinomial Naive Bayes (no sklearn vectoriser/classifier); hybrid policy |
| `entity_normalizer.py` | `DictionaryIndex` (aliases, case-sensitive aliases, fuzzy lookup), canonicalisation, temporal resolution |
| `slot_filler.py` | Explicit per-intent slot schemas, department role assignment, self/pronoun handling |
| `ambiguity.py` | Ambiguity records, clarification questions, final status |
| `schemas.py` | Entity types, intents, slot schemas, exceptions |
| `pipeline.py` | `NLUPipeline.parse(text, reference_date=None)` orchestration |

Config (no database lookups): `config/entities.json` (departments / applications / roles + aliases +
case-sensitive aliases), `config/patterns.json` (actions, temporal regexes, ID regexes, reason regex, intent cues
and weights, negators, unsupported-request cues, thresholds).

### NER conflict resolution (documented strategy)
1. **Rule candidates** (dictionary incl. multiword aliases, typo-tolerant fuzzy match for single-token departments/
   applications, employee-ID regexes, temporal regexes, action phrases, reason spans) are ranked by token length
   (longest first), then type priority `EMPLOYEE_IDENTIFIER > EFFECTIVE_DATE > ACCESS_ROLE > APPLICATION > DEPARTMENT > ACTION > REASON`,
   then exact-before-fuzzy, then position. A greedy non-overlapping selection is made; every discarded candidate is kept as a conflict record.
   (e.g. "Sales Force" -> APPLICATION beats "Sales" -> DEPARTMENT; "Finance Approver" -> ACCESS_ROLE beats "Finance".)
2. **CRF entities** are kept only if they do not overlap a selected rule entity (curated dictionaries/patterns win
   over a statistical guess). CRF is what finds PERSON, unknown department/application names and unusual phrasings.
3. CRF-only entities pass a cheap **plausibility check** (a pronoun/determiner/action word is never a PERSON; a date
   needs a digit or temporal word; an ID needs a digit).
4. Significant disagreements (different type, equal-length tie, or CRF probability >= 0.7) surface as an
   informational `overlapping_entities` ambiguity. Spans are never edited; `text[start:end] == entity.text` always holds.

**Offset convention:** 0-based Python string indices into the *original* input, `start` inclusive, `end` exclusive.
Possessive `'s` is excluded from the PERSON span ("Ananya's" -> `Ananya`). Typo corrections affect matching only.

### Intent classification
* **Rule baseline (explainable):** weighted regex cues over the (typo-corrected) token string; every matched cue is returned as `evidence`.
  A cue counts only if it is **not negated** (negator within 3 word-tokens, no clause break between). Negated strong cues put the intent
  in `negated_candidates` and weak cues cannot take over (`"No need to revoke my access to SAP"` is UNKNOWN, not ACCESS_REQUEST).
  Passive/question forms suppress imperative ones (`"Has my access been revoked?"` is a status query); a joiner subsumes a bundled
  access request; a `from <dept> ... to <dept>` pair promotes MOVER over JOINER/LEAVER; unsupported topics (passwords, payroll, annual leave...) are flagged.
  Competing strong intents raise `multiple_intents` instead of silently picking one.
* **Statistical baseline:** hand-implemented TF-IDF (`tf = 1+ln(count)`, `idf = ln((1+N)/(1+df))+1`, L2-normalised, unigrams+bigrams over
  entity-masked tokens) + multinomial Naive Bayes with Laplace smoothing. Separate `train()` / `predict()` / `save()` / `load()`.
* **Hybrid policy (default):** rules decide whenever any cue fires; Naive Bayes only fills the gap when no cue fired *and* there is no negation
  and no unsupported-topic signal, with posterior >= 0.7. Disagreement with a confident NB (>= 0.85) is recorded as an informational ambiguity.

### Confidence semantics
`confidence` is always accompanied by `confidence_type`:
`crf_marginal_mean` (mean CRF token marginal, model-based but **not calibrated**), `naive_bayes_posterior_uncalibrated`
(NB posteriors are typically over-confident), `heuristic` (rule margin `top/(top+second+1)`, or fuzzy-match string ratio), or `null` (exact dictionary/regex
match; no probability is claimed).

### Temporal resolution
Relative expressions are resolved against `reference_date` (argument, constructor, or `date.today()`; always echoed in `meta.reference_date`).
Bare weekday = first such day strictly after the reference date; `next <weekday>` is **ambiguous** when that day is still in the current ISO week
(blocking `ambiguous_date`, candidates listed); `end of the week`, `next week`, `this weekend`, `a few days` stay **unresolved** (value `null`, expression preserved);
day/month without year = next occurrence; numeric dates are `DD/MM/YYYY`; invalid dates (`31 February`) are unresolved.

### Slots
Every key of the intent's schema is always present (`null` / `[]` when empty). Required slots per intent:
JOINER `person`; MOVER `person`, `target_department`; LEAVER `person`; ACCESS_REQUEST / ACCESS_REVOCATION `person`, `applications`; ACCESS_STATUS_QUERY `person`.
`person` is satisfied by a name, an employee ID, or a self-reference (`subject_reference: "SELF"` for me/my/I; the standalone NLU never resolves who "me" is).
Departments get a role only from a cue word before them (`from`, `out of`, `leaving` -> source; `to`, `into`, `joining`, `for` -> target; `in` -> neutral); the first
department is never assumed to be the source and an uncued department is reported, not guessed. Unknown department/application names are kept in `unresolved`
and never placed in a slot. `status` is `PARSED`, `NEEDS_CLARIFICATION` (missing fields or any *blocking* ambiguity) or `UNKNOWN_INTENT`.

## Output example (real output, `reference_date=2026-10-15`)

**Input:** `Move Rahul Sharma from Engineering to Finance.`
```json
{
  "text": "Move Rahul Sharma from Engineering to Finance.",
  "intent": {
    "label": "MOVER",
    "confidence": 0.857,
    "confidence_type": "heuristic",
    "method": "rule_based"
  },
  "entities": [
    {
      "text": "Move",
      "type": "ACTION",
      "start": 0,
      "end": 4,
      "confidence": null,
      "method": "rule_based",
      "normalized": "MOVE"
    },
    {
      "text": "Rahul Sharma",
      "type": "PERSON",
      "start": 5,
      "end": 17,
      "confidence": 0.9994,
      "method": "crf",
      "normalized": "Rahul Sharma"
    },
    {
      "text": "Engineering",
      "type": "DEPARTMENT",
      "start": 23,
      "end": 34,
      "confidence": null,
      "method": "rule_based",
      "normalized": "Engineering"
    },
    {
      "text": "Finance",
      "type": "DEPARTMENT",
      "start": 38,
      "end": 45,
      "confidence": null,
      "method": "rule_based",
      "normalized": "Finance"
    }
  ],
  "slots": {
    "person": "Rahul Sharma",
    "employee_id": null,
    "subject_reference": null,
    "source_department": "Engineering",
    "target_department": "Finance",
    "effective_date": null,
    "reason": null
  },
  "unresolved": {},
  "missing_fields": [],
  "ambiguities": [],
  "clarification_questions": [],
  "status": "PARSED"
}
```

**Input:** `Revoke Ananya's Salesforce access at the end of the month.`
```json
{
  "text": "Revoke Ananya's Salesforce access at the end of the month.",
  "intent": {
    "label": "ACCESS_REVOCATION",
    "confidence": 0.75,
    "confidence_type": "heuristic",
    "method": "rule_based"
  },
  "entities": [
    {
      "text": "Revoke",
      "type": "ACTION",
      "start": 0,
      "end": 6,
      "confidence": null,
      "method": "rule_based",
      "normalized": "REVOKE_ACCESS"
    },
    {
      "text": "Ananya",
      "type": "PERSON",
      "start": 7,
      "end": 13,
      "confidence": 0.9978,
      "method": "crf",
      "normalized": "Ananya"
    },
    {
      "text": "Salesforce",
      "type": "APPLICATION",
      "start": 16,
      "end": 26,
      "confidence": null,
      "method": "rule_based",
      "normalized": "Salesforce"
    },
    {
      "text": "at the end of the month",
      "type": "EFFECTIVE_DATE",
      "start": 34,
      "end": 57,
      "confidence": null,
      "method": "rule_based",
      "normalized": {
        "expression": "at the end of the month",
        "value": "2026-10-31",
        "resolved": true,
        "kind": "end_of_period"
      }
    }
  ],
  "slots": {
    "person": "Ananya",
    "employee_id": null,
    "subject_reference": null,
    "applications": [
      "Salesforce"
    ],
    "access_roles": [],
    "effective_date": {
      "value": "2026-10-31",
      "expression": "at the end of the month",
      "resolved": true
    },
    "reason": null
  },
  "unresolved": {},
  "missing_fields": [],
  "ambiguities": [
    {
      "type": "partial_name",
      "blocking": false,
      "message": "Only 'Ananya' was given; a full name may be needed downstream to identify the employee.",
      "candidates": [],
      "field": "person"
    }
  ],
  "clarification_questions": [],
  "status": "PARSED"
}
```

**Input:** `Do not revoke my access.`
```json
{
  "text": "Do not revoke my access.",
  "intent": {
    "label": "UNKNOWN",
    "confidence": null,
    "confidence_type": null,
    "method": "rule_based"
  },
  "entities": [
    {
      "text": "revoke",
      "type": "ACTION",
      "start": 7,
      "end": 13,
      "confidence": null,
      "method": "rule_based",
      "normalized": "REVOKE_ACCESS"
    }
  ],
  "slots": {},
  "unresolved": {},
  "missing_fields": [],
  "ambiguities": [
    {
      "type": "negated_action",
      "blocking": true,
      "message": "The request negates an access revocation; no action is requested.",
      "candidates": [],
      "field": null
    }
  ],
  "clarification_questions": [
    "You mention NOT doing an access revocation. Do you want to cancel something, or request a different action?"
  ],
  "status": "UNKNOWN_INTENT"
}
```

**Input:** `Move him to Finance.`
```json
{
  "text": "Move him to Finance.",
  "intent": {
    "label": "MOVER",
    "confidence": 0.75,
    "confidence_type": "heuristic",
    "method": "rule_based"
  },
  "entities": [
    {
      "text": "Move",
      "type": "ACTION",
      "start": 0,
      "end": 4,
      "confidence": null,
      "method": "rule_based",
      "normalized": "MOVE"
    },
    {
      "text": "Finance",
      "type": "DEPARTMENT",
      "start": 12,
      "end": 19,
      "confidence": null,
      "method": "rule_based",
      "normalized": "Finance"
    }
  ],
  "slots": {
    "person": null,
    "employee_id": null,
    "subject_reference": null,
    "source_department": null,
    "target_department": "Finance",
    "effective_date": null,
    "reason": null
  },
  "unresolved": {},
  "missing_fields": [
    "person"
  ],
  "ambiguities": [
    {
      "type": "unresolved_pronoun",
      "blocking": true,
      "message": "A pronoun is used but no employee is named.",
      "candidates": [],
      "field": "person"
    }
  ],
  "clarification_questions": [
    "Who does the pronoun (he/she/they/him/her) refer to? Please give the employee's name or ID."
  ],
  "status": "NEEDS_CLARIFICATION"
}
```

Additional keys not in the minimal schema: `unresolved`, `meta`, per-intent `evidence`/`scores`/`candidates`/`statistical`, per-entity `normalized` /
`confidence_type` / `dictionary_match` / `negated` (ACTION). Ambiguity records look like
`{"type", "blocking", "message", "candidates", "field"}`.

## Data

`nlu/data/generate_datasets.py` (fixed seed) writes `ner_train/test.json` (text, char-span entities, tokens, BIO), `intent_train/test.json`, and
`pipeline_generated_test.json`. Train and test use **disjoint templates, person names, unknown department/application names, typo variants and reason phrases**.
`pipeline_test.json` (48 cases, built by `data/build_pipeline_test.py`) is hand-written end-to-end gold. Covered: paraphrases, multiword entities, missing/ambiguous fields, typos,
aliases, negation, mixed/conflicting instructions, relative dates, unknown names, repeated entity types, unsupported requests.

## Measured results (this repository, Python 3.12, reference date 2026-10-15)

All numbers below were produced by the evaluation scripts on the shipped models.

**NER, entity-level exact match (span + type), 316 test sentences / 1060 gold entities**

| | rules only | CRF only | **hybrid** |
|---|---|---|---|
| micro P / R / F1 | 0.990 / 0.737 / 0.845 | 0.962 / 0.924 / 0.942 | **0.983 / 0.977 / 0.980** |
| macro-F1 over types | 0.854 | 0.934 | **0.987** |

Hybrid per-type F1: ACCESS_ROLE 1.000, ACTION 0.972, APPLICATION 0.973, DEPARTMENT 0.978, EFFECTIVE_DATE 1.000, EMPLOYEE_IDENTIFIER 1.000, PERSON 0.976, REASON 1.000.

**Intent (316 test sentences)**: rules-only and hybrid accuracy 1.000 / macro-F1 1.000; Naive Bayes alone accuracy 0.842 / macro-F1 0.835.
Negation (32 negated sentences): action wrongly triggered 0% for rules/hybrid; Naive Bayes alone correctly abstained on only 28%, which is why the hybrid policy never lets NB override negation.

**End-to-end**: hand-written gold (48 cases): intent 1.000, slot exact-match 1.000 (45 cases with gold slots), status 1.000, negation 4/4, blocking-ambiguity F1 1.000.
Template-generated held-out set (316): intent 1.000, slot exact-match 0.968, status 0.978, blocking-ambiguity type P/R/F1 0.947 / 0.900 / 0.923, needs-clarification detection P/R 0.931 / 1.000.

### How to read these numbers (important)
* The data is **synthetic and template-derived**. The rule cues were written by the same author as the templates, so the 1.000 intent scores are an optimistic,
  in-distribution result, not evidence of production accuracy. The Naive Bayes result (0.84) is the better indicator of how much a statistical model learns from this synthetic data.
* Train and test templates are disjoint, but they come from one author and one style.
* **Development history disclosed:** after the first evaluation run (hybrid NER micro-F1 0.945; generated-set slot exact-match 0.835) I (a) fixed generator gold bugs
  (two aliases of the same department in one sentence), (b) added more person names, unknown department/application names and ~11 generic wording templates to the **training** data only,
  (c) added the CRF plausibility check, and (d) added role-assignment cues ("add X to the Y role", "remove X from the Y role") after a hand-written gold case failed.
  The test sets were not edited, but they were looked at while debugging, so treat the post-fix numbers as development-set quality rather than a clean blind test.
* Remaining failures are CRF errors on unseen sentence structures (e.g. an unseen department name tagged PERSON or APPLICATION, a missed single first name), which then show up as spurious `multiple_persons`/`unknown_application` clarifications.
  Run `evaluate_pipeline --show-failures` to list them.

## Limitations
* English only; short, single-request sentences. Long multi-sentence tickets are not segmented.
* PERSON recognition is purely statistical and depends on the training distribution; unseen multiword department names can be mistaken for people. No gazetteer of employees (by design, no DB).
* "Ambiguous names" are limited to flagging first-name-only mentions (`partial_name`, informational); directory disambiguation is out of scope.
* Pronouns are not resolved (no coreference); with no named person a pronoun triggers a clarification. A named person plus a pronoun is assumed consistent.
* Negation is a lexical window (3 tokens, clause-bounded). Entities are not tracked per clause, so mixed negation produces a `mixed_negation` clarification rather than a guess.
* Past-tense context ("he left last week") is read as another date, causing a `multiple_dates` clarification. This is conservative rather than wrong.
* REASON spans are flat and swallow entities inside them (e.g. a department named inside "because Finance was restructured").
* Fuzzy (typo) matching is limited to single-token departments/applications and a closed verb lexicon; multiword typos are not matched.
* Role assignment of departments needs a cue word; telegraphic input ("Move Rahul Sales Finance") gets a clarification.
* "need access" etc. are ACTION entities even when negated (the entity carries `negated: true`).
* Intent cues and dictionaries are hand-authored; extend `config/*.json` for new vocabularies (retrain the CRF/NB if you add training data).
