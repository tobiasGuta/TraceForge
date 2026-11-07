"""Tests for source-aware process queries and conservative correlation."""
from datetime import datetime, timedelta, timezone
import json
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from traceforge.app import app
from traceforge.db import database


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    monkeypatch.setenv("TRACEFORGE_DATA_DIR", str(tmp_path))
    with TestClient(app) as client:
        case_id = client.post("/api/cases", json={"name": "Investigation of several hosts"}).json()["id"]
        other_case = client.post("/api/cases", json={"name": "Unrelated investigation"}).json()["id"]
        with database() as db:
            for case in (case_id, other_case):
                db.execute(
                    """INSERT INTO evidence (id,case_id,filename,sha256,size_bytes,uploaded_at,status)
                       VALUES (?,?,?,?,?,?,?)""",
                    (case + "-evidence", case, "Windows.evtx", "0" * 64, 150,
                     "2026-04-01T00:00:00+00:00", "ready"),
                )
        yield client, case_id, other_case


def add_event(case_id, host, time, eid, provider, data, summary="Observed event"):
    with database() as db:
        cursor = db.execute(
            """INSERT INTO events
              (case_id,evidence_id,timestamp,event_id,record_id,host,channel,provider,
               account,summary,data_json,raw_xml)
              VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (case_id, case_id + "-evidence", time, eid, str(uuid4()), host,
             "Security" if eid == 4688 else "Sysmon/Operational",
             provider, data.get("SubjectUserName", ""), summary,
             json.dumps(data), "<Event/>"),
        )
        return cursor.lastrowid


SECURITY = "Microsoft-Windows-Security-Auditing"
SYSMON = "Microsoft-Windows-Sysmon"


def test_process_search_filters_case_host_schema_and_literal_wildcards(workspace):
    client, case_id, other_case = workspace
    stamp = "2026-03-10T15:00:00+00:00"
    add_event(case_id, "CORP-ALPHA", stamp, 4688, SECURITY, {
        "NewProcessName": r"C:\Windows\System32\audit_tool.exe",
        "NewProcessId": "0x1f4", "CommandLine": "audit_tool.exe /scan /label:100%"}),
    add_event(case_id, "CORP-BETA", stamp, 4688, SECURITY, {
        "NewProcessName": r"D:\Programs\editor.exe", "NewProcessId": "0x1f4"})
    add_event(case_id, "CORP-ALPHA", stamp, 1, SYSMON, {
        "Image": r"C:\Tools\helper.exe", "ProcessId": "600",
        "CommandLine": "helper.exe --process"})
    add_event(case_id, "CORP-ALPHA", stamp, 1, "Unrelated-Provider", {
        "Image": "not-a-sysmon-process"})
    add_event(other_case, "CORP-ALPHA", stamp, 4688, SECURITY, {
        "NewProcessName": r"C:\Windows\System32\audit_tool.exe"})
    all_processes = client.get(f"/api/cases/{case_id}/processes").json()
    assert all_processes["total"] == 3
    assert set(all_processes["hosts"]) == {"CORP-ALPHA", "CORP-BETA"}
    only_alpha = client.get(f"/api/cases/{case_id}/processes", params={
        "host": "CORP-ALPHA", "q": "100%"
    }).json()
    assert only_alpha["total"] == 1
    assert only_alpha["items"][0]["image"].endswith("audit_tool.exe")
    assert only_alpha["items"][0]["pid"] == "0x1f4"
    assert client.get(f"/api/cases/{case_id}/processes?q=helper").json()["items"][0]["source"] == "sysmon"
    assert client.get(f"/api/cases/{case_id}/processes?q=unrelated").json()["total"] == 0


def test_correlates_only_same_host_and_explicit_pid_candidates(workspace):
    client, case_id, other_case = workspace
    t0 = datetime(2026, 4, 1, 12, 0, tzinfo=timezone.utc)
    ts = lambda minutes: (t0 + timedelta(minutes=minutes)).isoformat()
    parent = add_event(case_id, "HOST-A", ts(0), 4688, SECURITY, {
        "NewProcessName": r"C:\Tools\parent.exe", "NewProcessId": "0x200"})
    child = add_event(case_id, "HOST-A", ts(3), 4688, SECURITY, {
        "NewProcessName": r"C:\Tools\child.exe", "NewProcessId": "0x300",
        "ProcessId": "0x200", "ParentProcessName": r"C:\Tools\parent.exe"})
    add_event(case_id, "HOST-B", ts(0), 4688, SECURITY, {
        "NewProcessName": r"C:\Tools\parent.exe", "NewProcessId": "0x200"})
    add_event(case_id, "HOST-A", ts(2), 4688, SECURITY, {
        "NewProcessName": r"C:\Tools\different.exe", "NewProcessId": "0x200"})
    add_event(other_case, "HOST-A", ts(1), 4688, SECURITY, {
        "NewProcessName": r"C:\Tools\parent.exe", "NewProcessId": "0x200"})
    unrelated = add_event(case_id, "HOST-A", ts(4), 4624, SECURITY, {
        "TargetUserName": "analyst"}, summary="Account logon")
    result = client.get(f"/api/cases/{case_id}/events/{child}/context").json()
    assert result["parent_total"] == 1
    assert result["parents"][0]["id"] == parent
    assert result["parents"][0]["confidence"] == "pid-candidate"
    assert "PID reuse" in result["note"]
    assert result["child_total"] == 0
    assert unrelated in [row["id"] for row in result["nearby"]]
    assert all(row["host"] == "HOST-A" for row in result["nearby"])
    reverse = client.get(f"/api/cases/{case_id}/events/{parent}/context").json()
    assert child in [row["id"] for row in reverse["children"]]
    assert all(row["confidence"] == "pid-candidate" for row in reverse["children"])


def test_source_guid_matches_and_unknown_relationships_remain_empty(workspace):
    client, case_id, _ = workspace
    t0 = "2026-04-01T10:00:00Z"
    t1 = "2026-04-01T10:02:00Z"
    parent = add_event(case_id, "WKS-ONE", t0, 1, SYSMON, {
        "Image": r"C:\Monitor\service.exe", "ProcessId": "100",
        "ProcessGuid": "{A-B-C}"})
    child = add_event(case_id, "WKS-ONE", t1, 1, SYSMON, {
        "Image": r"C:\Monitor\worker.exe", "ProcessId": "101",
        "ParentProcessId": "100", "ParentProcessGuid": "{a-b-c}"})
    result = client.get(f"/api/cases/{case_id}/events/{child}/context").json()
    assert result["parents"][0]["id"] == parent
    assert result["parents"][0]["confidence"] == "source-guid"

    missing = add_event(case_id, "WKS-TWO", t1, 4688, SECURITY, {
        "NewProcessName": r"C:\Tools\orphan.exe", "NewProcessId": "0x200",
        "ProcessId": "0x999"})
    unlinked = client.get(f"/api/cases/{case_id}/events/{missing}/context").json()
    assert unlinked["parents"] == [] and unlinked["children"] == []
    assert client.get(f"/api/cases/{case_id}/events/999999/context").status_code == 404


def test_event_data_filters_are_dynamic_and_scoped(workspace):
    client, case_id, _ = workspace
    add_event(case_id, "HOST-C", "2026-04-01T12:00:00Z", 4500,
              "Vendor-Provider", {"CustomField": "value_100%", "Mode": "explicit"},
              "Vendor audit")
    add_event(case_id, "HOST-D", "2026-04-01T12:00:00Z", 4500,
              "Vendor-Provider", {"CustomField": "another value"})
    keys = client.get(f"/api/cases/{case_id}/field-keys").json()
    assert "CustomField" in keys
    assert "Mode" in keys
    assert "HOST-C" in client.get(f"/api/cases/{case_id}/hosts").json()
    matched = client.get(f"/api/cases/{case_id}/events", params={
        "field_key": "CustomField", "field_value": "100%", "host": "HOST-C"
    }).json()
    assert matched["total"] == 1
    assert client.get(f"/api/cases/{case_id}/events?field_key=Mode").json()["total"] == 1
    assert client.get(f"/api/cases/{case_id}/events?field_key=Imaginary").json()["total"] == 0
    assert client.get(f"/api/cases/{case_id}/events?field_value=oops").status_code == 422
