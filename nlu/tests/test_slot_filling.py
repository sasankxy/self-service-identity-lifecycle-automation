def test_spec_example_mover(pipe):
    r = pipe.parse("Move Rahul Sharma from Engineering to Finance.")
    assert r["intent"]["label"] == "MOVER" and r["status"] == "PARSED"
    assert (r["slots"]["person"], r["slots"]["source_department"], r["slots"]["target_department"]) == \
        ("Rahul Sharma", "Engineering", "Finance")
    assert r["missing_fields"] == []


def test_spec_example_self_access_request_does_not_invent_employee(pipe):
    r = pipe.parse("Give me access to SAP.")
    assert r["intent"]["label"] == "ACCESS_REQUEST"
    assert r["slots"]["applications"] == ["SAP"] and r["slots"]["person"] is None
    assert r["slots"]["subject_reference"] == "SELF"


def test_spec_example_revocation_with_resolved_date(pipe):
    r = pipe.parse("Revoke Ananya's Salesforce access at the end of the month.")
    assert r["slots"]["person"] == "Ananya" and r["slots"]["applications"] == ["Salesforce"]
    assert r["slots"]["effective_date"] == {"value": "2026-10-31", "expression": "at the end of the month", "resolved": True}
    ent = [e for e in r["entities"] if e["type"] == "PERSON"][0]
    assert ent["text"] == "Ananya"  # possessive 's excluded from the span


def test_first_department_is_not_assumed_to_be_source(pipe):
    r = pipe.parse("Move Rahul Sharma to Finance from Engineering.")
    assert r["slots"]["source_department"] == "Engineering" and r["slots"]["target_department"] == "Finance"


def test_single_department_without_cue_is_not_guessed(pipe):
    r = pipe.parse("Move Rahul Sharma to Finance and Sales.")
    assert r["slots"]["target_department"] == "Finance"
    assert any(a["type"] == "ambiguous_department_roles" for a in r["ambiguities"])
    assert r["status"] == "NEEDS_CLARIFICATION"


def test_same_source_and_target_conflict(pipe):
    r = pipe.parse("Move Rahul Sharma from Finance to Finance.")
    assert any(a["type"] == "same_source_and_target" for a in r["ambiguities"])


def test_department_is_not_an_access_role(pipe):
    r = pipe.parse("Give Priya Nair access to SAP for Finance.")
    assert r["slots"]["access_roles"] == [] and "department" not in r["slots"]
    assert any(a["type"] == "unused_entity" and not a["blocking"] for a in r["ambiguities"])


def test_role_and_multiple_applications(pipe):
    r = pipe.parse("Grant Priya Nair admin access to Salesforce and Jira.")
    assert r["slots"]["access_roles"] == ["Administrator"]
    assert r["slots"]["applications"] == ["Salesforce", "Jira"]


def test_unknown_application_and_department_are_not_invented(pipe):
    r = pipe.parse("Give me access to Zendesk.")
    assert r["slots"]["applications"] == [] and "applications" in r["missing_fields"]
    assert r["unresolved"]["applications"] == ["Zendesk"] and r["status"] == "NEEDS_CLARIFICATION"
    r = pipe.parse("Rahul Sharma moves to Treasury.")
    assert r["slots"]["target_department"] is None and r["unresolved"]["department"] == ["Treasury"]


def test_typo_resolved_but_reported(pipe):
    r = pipe.parse("Priya Nair is joining the Enginering team tomorrow.")
    assert r["slots"]["target_department"] == "Engineering"
    assert any(a["type"] == "fuzzy_match" for a in r["ambiguities"])


def test_missing_required_fields(pipe):
    r = pipe.parse("Move Rahul Sharma.")
    assert r["missing_fields"] == ["target_department"] and r["status"] == "NEEDS_CLARIFICATION"
    assert any("department" in q for q in r["clarification_questions"])


def test_dates_resolved_unresolved_and_ambiguous(pipe):
    r = pipe.parse("Revoke Rahul Sharma's SAP access tomorrow.")
    assert r["slots"]["effective_date"]["value"] == "2026-10-16"
    r = pipe.parse("Onboard Meera Krishnan into Marketing next week.")
    d = r["slots"]["effective_date"]
    assert d["value"] is None and d["resolved"] is False and r["status"] == "PARSED"  # unresolved, not invented
    r = pipe.parse("Revoke Priya's Jira access next Friday.")
    assert r["slots"]["effective_date"]["value"] is None and r["status"] == "NEEDS_CLARIFICATION"
    assert any(a["type"] == "ambiguous_date" for a in r["ambiguities"])
    assert pipe.parse("Offboard EMP4821 on 2026-11-30.")["slots"]["effective_date"]["value"] == "2026-11-30"
    assert pipe.parse("Offboard EMP4821 in two weeks.")["slots"]["effective_date"]["value"] == "2026-10-29"


def test_invalid_calendar_date_stays_unresolved(pipe):
    r = pipe.parse("Offboard EMP4821 on 31 February.")
    assert r["slots"]["effective_date"]["value"] is None


def test_employee_id_satisfies_person_requirement(pipe):
    r = pipe.parse("Offboard EMP4821 tomorrow.")
    assert r["slots"]["employee_id"] == "EMP4821" and r["missing_fields"] == [] and r["status"] == "PARSED"


def test_reason_slot(pipe):
    r = pipe.parse("Please transfer Vikram Singh from Sales to Marketing because of a restructure.")
    assert r["slots"]["reason"] == "because of a restructure"


def test_output_schema_is_stable(pipe):
    r = pipe.parse("Hello")
    assert set(r) == {"text", "intent", "entities", "slots", "unresolved", "missing_fields", "ambiguities",
                      "clarification_questions", "status", "meta"}
    assert {"label", "confidence", "confidence_type", "method"} <= set(r["intent"])
    import json
    json.dumps(r)  # JSON-compatible
