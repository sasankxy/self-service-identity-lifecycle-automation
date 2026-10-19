"""Writes data/pipeline_test.json: HAND-WRITTEN end-to-end gold cases (reference date 2026-10-15).
Gold slots list only non-default values; omitted slots default to None / []. `intent` may be a list when the
text is genuinely ambiguous between several intents; `slots: None` skips slot comparison."""
import json
from pathlib import Path

D = lambda v, e, r=True: {"value": v, "expression": e, "resolved": r}
C = []
def case(text, intent, slots=None, missing=(), amb=(), status="PARSED", negated=False):
    C.append({"text": text, "intent": intent, "slots": slots, "missing_fields": list(missing),
              "blocking_ambiguities": sorted(amb), "status": status, "negated": negated})
NC, UI = "NEEDS_CLARIFICATION", "UNKNOWN_INTENT"

case("Move Rahul Sharma from Engineering to Finance.", "MOVER", {"person": "Rahul Sharma", "source_department": "Engineering", "target_department": "Finance"})
case("Give me access to SAP.", "ACCESS_REQUEST", {"subject_reference": "SELF", "applications": ["SAP"]})
case("Revoke Ananya's Salesforce access at the end of the month.", "ACCESS_REVOCATION", {"person": "Ananya", "applications": ["Salesforce"], "effective_date": D("2026-10-31", "at the end of the month")})
case("Do not revoke my access.", "UNKNOWN", {}, amb=["negated_action"], status=UI, negated=True)
case("Do not revoke Rahul's access to SAP.", "UNKNOWN", {}, amb=["negated_action"], status=UI, negated=True)
case("Please do not give Rahul Sharma access to SAP, cancel it.", "UNKNOWN", {}, amb=["negated_action"], status=UI, negated=True)
case("Move Rahul Sharma to Finance.", "MOVER", {"person": "Rahul Sharma", "target_department": "Finance"})
case("Move Rahul Sharma.", "MOVER", {"person": "Rahul Sharma"}, missing=["target_department"], status=NC)
case("Move him to Finance.", "MOVER", {"target_department": "Finance"}, missing=["person"], amb=["unresolved_pronoun"], status=NC)
case("Give access to SAP.", "ACCESS_REQUEST", {"applications": ["SAP"]}, missing=["person"], status=NC)
case("Give me access to Zendesk.", "ACCESS_REQUEST", {"subject_reference": "SELF"}, missing=["applications"], amb=["unknown_application"], status=NC)
case("Move Rahul Sharma from Engineering to Engineering.", "MOVER", {"person": "Rahul Sharma", "source_department": "Engineering", "target_department": "Engineering"}, amb=["same_source_and_target"], status=NC)
case("Move Rahul Sharma to Finance and Sales.", "MOVER", {"person": "Rahul Sharma", "target_department": "Finance"}, amb=["ambiguous_department_roles"], status=NC)
case("Revoke Rahul Sharma's SAP access tomorrow.", "ACCESS_REVOCATION", {"person": "Rahul Sharma", "applications": ["SAP"], "effective_date": D("2026-10-16", "tomorrow")})
case("Revoke Priya's Jira access next Friday.", "ACCESS_REVOCATION", {"person": "Priya", "applications": ["Jira"], "effective_date": D(None, "next Friday", False)}, amb=["ambiguous_date"], status=NC)
case("Onboard Meera Krishnan into Marketing next week.", "JOINER", {"person": "Meera Krishnan", "target_department": "Marketing", "effective_date": D(None, "next week", False)})
case("Does Priya Nair have access to Jira?", "ACCESS_STATUS_QUERY", {"person": "Priya Nair", "applications": ["Jira"]})
case("What access does Arjun Mehta have?", "ACCESS_STATUS_QUERY", {"person": "Arjun Mehta"})
case("Offboard EMP4821 tomorrow.", "LEAVER", {"employee_id": "EMP4821", "effective_date": D("2026-10-16", "tomorrow")})
case("Revoke access for Rahul Sharma and Priya Nair on SAP.", "ACCESS_REVOCATION", {"applications": ["SAP"]}, missing=["person"], amb=["multiple_persons"], status=NC)
case("Grant Priya Nair admin access to Salesforce and Jira.", "ACCESS_REQUEST", {"person": "Priya Nair", "access_roles": ["Administrator"], "applications": ["Salesforce", "Jira"]})
case("Reset my password.", "UNKNOWN", {}, amb=["unsupported_request"], status=UI)
case("Hello", "UNKNOWN", {}, amb=["unknown_intent"], status=UI)
case("Please revoke Priya's Jira access, she is leaving the company.", ["ACCESS_REVOCATION", "LEAVER"], None, amb=["multiple_intents"], status=NC)
case("Revoke Rahul's access to SAP and give him access to Jira.", ["ACCESS_REVOCATION", "ACCESS_REQUEST"], None, amb=["multiple_intents"], status=NC)
case("Don't move Priya Nair to Finance; revoke her Jira access instead.", "ACCESS_REVOCATION", {"person": "Priya Nair", "applications": ["Jira"]}, amb=["mixed_negation"], status=NC, negated=True)
case("I am leaving the company on Friday.", "LEAVER", {"subject_reference": "SELF", "effective_date": D("2026-10-16", "Friday")})
case("Please transfer Vikram Singh from Sales to Marketing because of a restructure.", "MOVER", {"person": "Vikram Singh", "source_department": "Sales", "target_department": "Marketing", "reason": "because of a restructure"})
case("Priya Nair is joining the Enginering team tomorrow.", "JOINER", {"person": "Priya Nair", "target_department": "Engineering", "effective_date": D("2026-10-16", "tomorrow")})
case("Check access for EMP-7712 on Workday.", "ACCESS_STATUS_QUERY", {"employee_id": "EMP7712", "applications": ["Workday"]})
case("Move Rahul Sharma from Finance.", "MOVER", {"person": "Rahul Sharma", "source_department": "Finance"}, missing=["target_department"], status=NC)
case("Remove access to Slack for Isha Kapoor.", "ACCESS_REVOCATION", {"person": "Isha Kapoor", "applications": ["Slack"]})
case("Can I get admin access to GitHub?", "ACCESS_REQUEST", {"subject_reference": "SELF", "access_roles": ["Administrator"], "applications": ["GitHub"]})
case("Rahul Sharma moves to Treasury.", "MOVER", {"person": "Rahul Sharma"}, missing=["target_department"], amb=["unknown_department"], status=NC)
case("Revoke my access.", "ACCESS_REVOCATION", {"subject_reference": "SELF"}, missing=["applications"], status=NC)
case("I need access to Jira in 2 weeks.", "ACCESS_REQUEST", {"subject_reference": "SELF", "applications": ["Jira"], "effective_date": D("2026-10-29", "in 2 weeks")})
case("Terminate access to SAP for Rahul Sharma.", "ACCESS_REVOCATION", {"person": "Rahul Sharma", "applications": ["SAP"]})
case("She needs access to Tableau.", "ACCESS_REQUEST", {"applications": ["Tableau"]}, missing=["person"], amb=["unresolved_pronoun"], status=NC)
case("Offboard Rahul Sharma and revoke his SAP access.", ["LEAVER", "ACCESS_REVOCATION"], None, amb=["multiple_intents"], status=NC)
case("Show me what applications Rahul Sharma can access.", "ACCESS_STATUS_QUERY", {"person": "Rahul Sharma"})
case("Rahul Sharma is on annual leave next Monday.", "UNKNOWN", {}, amb=["unsupported_request"], status=UI)
case("Move Rahul Sharma from Engineering to Finance on 2026-11-30 due to a promotion.", "MOVER", {"person": "Rahul Sharma", "source_department": "Engineering", "target_department": "Finance", "effective_date": D("2026-11-30", "2026-11-30"), "reason": "due to a promotion"})
case("Revoke SFDC access for Rahul Sharma.", "ACCESS_REVOCATION", {"person": "Rahul Sharma", "applications": ["Salesforce"]})
case("Add Rahul Sharma to the Finance Approver role in SAP.", "ACCESS_REQUEST", {"person": "Rahul Sharma", "access_roles": ["Finance Approver"], "applications": ["SAP"]})
case("Hi, could you check whether Priya Nair still has access to ServiceNow?", "ACCESS_STATUS_QUERY", {"person": "Priya Nair", "applications": ["ServiceNow"]})
case("Priya Nair and Rahul Sharma are both joining Finance tomorrow.", "JOINER", {"target_department": "Finance", "effective_date": D("2026-10-16", "tomorrow")}, missing=["person"], amb=["multiple_persons"], status=NC)
case("Rahul Sharma is leaving Engineering for Finance next Monday.", "MOVER", {"person": "Rahul Sharma", "source_department": "Engineering", "target_department": "Finance", "effective_date": D("2026-10-19", "next Monday")})
case("Revke Ananya Iyer's Jira acess today.", "ACCESS_REVOCATION", {"person": "Ananya Iyer", "applications": ["Jira"], "effective_date": D("2026-10-15", "today")})

Path(__file__).with_name("pipeline_test.json").write_text(json.dumps(C, indent=1, ensure_ascii=False))
print(len(C), "hand-written cases")
