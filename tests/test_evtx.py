from traceforge.evtx import parse_event_xml, TRIAGE_RULES

SAMPLE = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System><Provider Name="Microsoft-Windows-Security-Auditing"/>
  <EventID>1102</EventID><TimeCreated SystemTime="2026-10-10T12:00:00.000Z"/>
  <EventRecordID>88</EventRecordID><Channel>Security</Channel><Computer>LAB-PC</Computer>
  </System><EventData><Data Name="SubjectUserName">analyst</Data></EventData></Event>"""


def test_normalizes_metadata_and_preserves_xml():
    event = parse_event_xml(SAMPLE)
    assert event["event_id"] == 1102
    assert event["host"] == "LAB-PC"
    assert event["account"] == "analyst"
    assert event["record_id"] == "88"
    assert event["timestamp"].endswith("Z")
    assert event["data"]["SubjectUserName"] == "analyst"
    assert event["raw_xml"] == SAMPLE


def test_triage_is_not_blanket_powershell_alert():
    assert 1102 in TRIAGE_RULES
    assert 4104 not in TRIAGE_RULES
    assert 4624 not in TRIAGE_RULES
