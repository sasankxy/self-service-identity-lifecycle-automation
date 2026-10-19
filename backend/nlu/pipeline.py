"""Public entry point: NLUPipeline.parse(text) -> JSON-compatible dict."""
from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Optional, Union

from . import ambiguity
from .config_loader import DEFAULT_MODELS_DIR, load_configs
from .entity_normalizer import DictionaryIndex, EntityNormalizer
from .features import Lexicons
from .intent_classifier import HybridIntentClassifier, NaiveBayesIntentClassifier, RuleBasedIntentClassifier
from .ner import CRFNER, HybridNER, RuleBasedNER
from .preprocessing import negated_at, preprocess
from .schemas import (OFFSET_CONVENTION, SLOT_SCHEMAS, STATUS_UNKNOWN_INTENT, LIST_SLOTS)
from .slot_filler import SlotFiller

CRF_MODEL_NAME = "ner_crf.crfsuite"
NB_MODEL_NAME = "intent_nb.json"


class NLUPipeline:
    """Standalone NLU pipeline.

    ner_mode:    "hybrid" (rules + CRF, default) | "rules_only" | "crf_only"
    intent_mode: "hybrid" (rules, NB fallback, default) | "rules_only" | "nb_only"
    Statistical modes raise MissingDependencyError / ModelNotTrainedError if unavailable; there is no
    silent fallback - choose "rules_only" explicitly if you want a rules-only pipeline.
    """

    def __init__(self, config_dir=None, models_dir=None, ner_mode="hybrid", intent_mode="hybrid",
                 reference_date: Optional[date] = None, entities_cfg: Optional[dict] = None):
        self.entities_cfg, self.patterns_cfg = load_configs(config_dir)
        if entities_cfg is not None:      # e.g. departments/applications loaded from the directory database
            self.entities_cfg = entities_cfg
        models_dir = Path(models_dir) if models_dir else DEFAULT_MODELS_DIR
        self.reference_date = reference_date
        self.typo_lexicon = self.patterns_cfg["typo_lexicon"]
        index = DictionaryIndex(self.entities_cfg, self.patterns_cfg)
        self.lexicons = Lexicons(self.entities_cfg, self.patterns_cfg)
        crf = None
        if ner_mode != "rules_only":
            crf = CRFNER(self.lexicons, self.typo_lexicon).load(models_dir / CRF_MODEL_NAME)
        self.ner = HybridNER(RuleBasedNER(self.entities_cfg, self.patterns_cfg, index), crf, ner_mode)
        nb = None
        if intent_mode != "rules_only":
            nb = NaiveBayesIntentClassifier(self.lexicons, self.entities_cfg, self.typo_lexicon).load(models_dir / NB_MODEL_NAME)
        self.intent = HybridIntentClassifier(RuleBasedIntentClassifier(self.patterns_cfg), nb, self.patterns_cfg, intent_mode)
        self.normalizer = EntityNormalizer(index)
        self.filler = SlotFiller(self.patterns_cfg)
        self.ner_mode, self.intent_mode = ner_mode, intent_mode

    def parse(self, text: str, reference_date: Optional[date] = None) -> dict:
        if not isinstance(text, str):
            raise TypeError("text must be a str")
        ref = reference_date or self.reference_date or date.today()
        doc = preprocess(text, self.typo_lexicon)
        entities, conflicts = self.ner.extract(doc)
        for e in entities:
            assert text[e.start:e.end] == e.text
            self.normalizer.normalize(e, ref)
            if e.type == "ACTION":
                e.negated = negated_at(doc.tokens, doc.span_to_tokens(e.start, e.end)[0],
                                       set(self.patterns_cfg["negators"]), set(self.patterns_cfg["clause_break_words"]),
                                       self.patterns_cfg["negation_window"])
        intent = self.intent.classify(doc, entities)
        sr = self.filler.fill(intent["label"], doc, entities)
        ambs, questions, status = ambiguity.analyze(intent, sr, entities, conflicts,
                                                    self.patterns_cfg["unknown_intent_question"])
        if not text.strip():
            status = STATUS_UNKNOWN_INTENT
        intent_out = {"label": intent["label"], "confidence": intent["confidence"],
                      "confidence_type": intent["confidence_type"], "method": intent.get("method", "rule_based"),
                      "scores": intent["scores"], "evidence": intent["evidence"]}
        if intent.get("candidates"):
            intent_out["candidates"] = intent["candidates"]
        if intent.get("secondary_intents"):
            intent_out["secondary_intents"] = intent["secondary_intents"]
        if intent.get("negated_candidates"):
            intent_out["negated_candidates"] = intent["negated_candidates"]
        if intent.get("statistical"):
            intent_out["statistical"] = {"label": intent["statistical"]["label"],
                                         "probability": intent["statistical"]["probability"],
                                         "confidence_type": intent["statistical"]["confidence_type"]}
        slots = dict(sr.slots)
        return {"text": text, "intent": intent_out, "entities": [e.to_dict() for e in entities],
                "slots": slots, "unresolved": sr.unresolved, "missing_fields": sr.missing if intent["label"] != "UNKNOWN" else [],
                "ambiguities": ambs, "clarification_questions": questions, "status": status,
                "meta": {"ner_mode": self.ner_mode, "intent_mode": self.intent_mode,
                         "reference_date": ref.isoformat(), "offset_convention": OFFSET_CONVENTION}}
