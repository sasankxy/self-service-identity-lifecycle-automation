import time

import pytest

from app.agents import capabilities as C
from tests.agents.unit.conftest import principal

SECRET = "s" * 48


def test_ceiling_follows_portal_permissions():
    assert C.tools_for(principal("iam_admin")) == C.READ_TOOLS | C.WRITE_TOOLS
    assert C.tools_for(principal("auditor")) == C.READ_TOOLS
    assert C.tools_for(principal("employee")) == C.SELF_READ_TOOLS | C.SELF_WRITE_TOOLS     # self-service, own identity only
    assert not C.tools_for(principal("approver")) & C.WRITE_TOOLS


def test_mint_never_exceeds_ceiling():
    cap = C.mint(principal("auditor"), tools={"deprovision_user", "inspect_user_access"})
    assert cap.tools == {"inspect_user_access"}


def test_narrowed_is_never_wider():
    cap = C.mint(principal("iam_admin"), targets={"a", "b"})
    sub = cap.narrowed(tools={"inspect_user_access", "made_up_tool"}, targets={"b", "c"})
    assert sub.tools == {"inspect_user_access"} and sub.targets == {"b"}
    assert not sub.allows_target("c")


def test_wildcard_target():
    cap = C.mint(principal("iam_admin"))
    assert cap.allows_target("anything")


def test_encode_decode_roundtrip():
    cap = C.mint(principal("iam_admin"), targets={"id-1"})
    back = C.decode(C.encode(cap, SECRET), SECRET)
    assert back == cap


@pytest.mark.parametrize("mutate", [
    lambda t: t[:-2] + ("A" if t[-2] != "A" else "B") + t[-1],           # signature
    lambda t: ("e" if t[0] != "e" else "f") + t[1:],                       # body
    lambda t: t.replace(".", ""),                                          # structure
])
def test_tampered_token_rejected(mutate):
    tok = C.encode(C.mint(principal("employee")), SECRET)
    with pytest.raises(C.CapabilityError):
        C.decode(mutate(tok), SECRET)


def test_wrong_secret_and_expiry():
    tok = C.encode(C.mint(principal("employee"), ttl_s=60), SECRET)
    with pytest.raises(C.CapabilityError) as e:
        C.decode(tok, "t" * 48)
    assert e.value.code == "bad_signature"
    with pytest.raises(C.CapabilityError) as e:
        C.decode(tok, SECRET, now=time.time() + 120)
    assert e.value.code == "expired"


def test_short_secret_refused():
    with pytest.raises(C.CapabilityError):
        C.encode(C.mint(principal("employee")), "short")
