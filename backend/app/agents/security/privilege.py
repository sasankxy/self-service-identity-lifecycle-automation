"""Verifier rules: agent-layer checks applied ON TOP of the policy engine's decision.

They can only make a decision stricter (AUTO -> APPROVAL -> DENY), never looser, so they cannot weaken the PDP. They exist because
an agent acting for a human adds risks a form does not have: a person asking the assistant to grant *themselves* access, or a
single conversational turn that quietly pulls in high-risk entitlements.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from app.services import policy

ESCALATING_RISK = ("high", "critical")


@dataclass
class Verdict:
    decision: str
    reasons: list[str] = field(default_factory=list)
    rules: list[str] = field(default_factory=list)      # machine ids, for audit and the adversarial suite


def stricter(a: str, b: str) -> str:
    return max(a, b, key=lambda d: policy._SEVERITY[d])


def is_self(actor_email: str, identity_email: str | None) -> bool:
    return bool(identity_email) and actor_email.strip().lower() == identity_email.strip().lower()


def verify(plan, actor_email: str) -> Verdict:
    """`plan` is a policy.Plan (duck-typed so the rules are unit-testable without a database)."""
    v = Verdict(decision=plan.decision)
    if plan.decision in (policy.CLARIFY, policy.NOOP, policy.DENY):
        return v

    def bump(decision: str, rule: str, reason: str) -> None:
        v.decision = stricter(v.decision, decision)
        v.rules.append(rule)
        v.reasons.append(reason)

    me = is_self(actor_email, getattr(plan.identity, "email", None))
    if me and plan.kind in ("mover", "leaver"):
        bump(policy.DENY, "self_lifecycle_change", "You cannot move or offboard your own identity through the assistant; ask your manager or IAM.")
    elif me and plan.adds:
        bump(policy.APPROVAL, "self_grant", "Access you request for yourself always needs a second person to approve it.")

    risky = [l for l in plan.adds if l.risk_level in ESCALATING_RISK]
    if risky and v.decision == policy.AUTO:
        bump(policy.APPROVAL, "high_risk_grant", "Agent-initiated grants of high or critical risk access always need a human approver: "
             + ", ".join(f"{l.name} ({l.risk_level})" for l in risky[:5]) + ".")
    return v
