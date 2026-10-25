"""Verifier: may only make the policy decision stricter."""
import pytest

from app.agents.security.privilege import stricter, verify
from app.services import policy
from tests.agents.unit.conftest import fake_identity, fake_line, fake_plan

ME = "kai.chen@corp.test"


def test_self_move_and_self_offboard_denied():
    for kind in ("mover", "leaver"):
        v = verify(fake_plan(kind, policy.APPROVAL, identity=fake_identity(ME), lines=[fake_line("x")]), ME)
        assert v.decision == policy.DENY and "self_lifecycle_change" in v.rules


def test_self_grant_needs_approval_even_when_policy_says_auto():
    v = verify(fake_plan("access_request", policy.AUTO, identity=fake_identity(ME.upper()), lines=[fake_line("Jira User")]), ME)
    assert v.decision == policy.APPROVAL and v.rules == ["self_grant"]


def test_self_revocation_allowed():
    v = verify(fake_plan("access_revocation", policy.AUTO, identity=fake_identity(ME), lines=[fake_line("Jira User", action="remove")]), ME)
    assert v.decision == policy.AUTO and not v.rules


@pytest.mark.parametrize("risk", ["high", "critical"])
def test_high_risk_grant_escalated(risk):
    v = verify(fake_plan("access_request", policy.AUTO, lines=[fake_line("AWS Admin", risk)]), "boss@corp.test")
    assert v.decision == policy.APPROVAL and "high_risk_grant" in v.rules


def test_low_risk_for_someone_else_untouched():
    v = verify(fake_plan("access_request", policy.AUTO, lines=[fake_line("Slack", "low")]), "boss@corp.test")
    assert v.decision == policy.AUTO and not v.rules


@pytest.mark.parametrize("decision", [policy.DENY, policy.CLARIFY, policy.NOOP])
def test_never_loosens_terminal_decisions(decision):
    v = verify(fake_plan("mover", decision, identity=fake_identity(ME), lines=[fake_line("x", "critical")]), ME)
    assert v.decision == decision


def test_stricter_is_monotonic():
    order = [policy.NOOP, policy.AUTO, policy.APPROVAL, policy.DENY]
    for i, a in enumerate(order):
        for b in order[i:]:
            assert stricter(a, b) == b and stricter(b, a) == b
