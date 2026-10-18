"""Shared constants, slot schemas, exceptions and the Entity container."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

ENTITY_TYPES = ("PERSON", "EMPLOYEE_IDENTIFIER", "DEPARTMENT", "APPLICATION",
                "ACCESS_ROLE", "ACTION", "EFFECTIVE_DATE", "REASON")
INTENTS = ("JOINER", "MOVER", "LEAVER", "ACCESS_REQUEST", "ACCESS_REVOCATION",
           "ACCESS_STATUS_QUERY", "UNKNOWN")

STATUS_PARSED = "PARSED"
STATUS_NEEDS_CLARIFICATION = "NEEDS_CLARIFICATION"
STATUS_UNKNOWN_INTENT = "UNKNOWN_INTENT"

OFFSET_CONVENTION = ("0-based Python string offsets into the original input; start inclusive, "
                     "end exclusive; text[start:end] == entity text")

_ACCESS_SLOTS = ("person", "employee_id", "subject_reference", "applications",
                 "access_roles", "effective_date", "reason")

# Explicit slot schema per intent. Every key is always present in the output (None / []).
SLOT_SCHEMAS: Dict[str, Tuple[str, ...]] = {
    "JOINER": ("person", "employee_id", "subject_reference", "target_department",
               "effective_date", "reason", "applications", "access_roles"),
    "MOVER": ("person", "employee_id", "subject_reference", "source_department",
              "target_department", "effective_date", "reason"),
    "LEAVER": ("person", "employee_id", "subject_reference", "department",
               "effective_date", "reason"),
    "ACCESS_REQUEST": _ACCESS_SLOTS,
    "ACCESS_REVOCATION": _ACCESS_SLOTS,
    "ACCESS_STATUS_QUERY": ("person", "employee_id", "subject_reference", "applications", "access_roles"),
    "UNKNOWN": (),
}
# "person" is satisfied by any of person / employee_id / subject_reference == "SELF".
REQUIRED_SLOTS: Dict[str, Tuple[str, ...]] = {
    "JOINER": ("person",),
    "MOVER": ("person", "target_department"),
    "LEAVER": ("person",),
    "ACCESS_REQUEST": ("person", "applications"),
    "ACCESS_REVOCATION": ("person", "applications"),
    "ACCESS_STATUS_QUERY": ("person",),
    "UNKNOWN": (),
}
LIST_SLOTS = ("applications", "access_roles")


class MissingDependencyError(ImportError):
    """A required (statistical) dependency is not installed."""


class ModelNotTrainedError(RuntimeError):
    """A trained model artefact is missing; run the training script."""


@dataclass
class Entity:
    text: str
    type: str
    start: int
    end: int
    confidence: Optional[float] = None
    confidence_type: Optional[str] = None   # "crf_marginal_mean" | "heuristic" | None
    method: str = "rule_based"              # rule_based | rule_based_fuzzy | crf
    normalized: Any = None
    match: Optional[str] = None             # exact | fuzzy | None (dictionary entities)
    negated: Optional[bool] = None          # only set for ACTION entities

    def overlaps(self, other: "Entity") -> bool:
        return self.start < other.end and other.start < self.end

    def to_dict(self) -> Dict[str, Any]:
        d = {"text": self.text, "type": self.type, "start": self.start, "end": self.end,
             "confidence": self.confidence, "confidence_type": self.confidence_type,
             "method": self.method, "normalized": self.normalized}
        if self.type in ("DEPARTMENT", "APPLICATION", "ACCESS_ROLE"):
            d["dictionary_match"] = self.match
        if self.type == "ACTION":
            d["negated"] = bool(self.negated)
        return d
