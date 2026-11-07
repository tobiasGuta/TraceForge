from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from traceforge.app import app
from traceforge.evtx import parse_event_xml
from test_evtx import SAMPLE


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("TRACEFORGE_DATA_DIR", str(tmp_path))
    with TestClient(app) as test_client:
        yield test_client


def create_case(client):
    result = client.post("/api/cases", json={"name": "Lab evidence", "description": "Sample"})
    assert result.status_code == 201
    return result.json()["id"]


def test_initial_dashboard_and_empty_case(client):
    assert client.get("/api/health").json()["status"] == "ok"
    assert client.get("/").status_code == 200
    case_id = create_case(client)
    assert client.get("/api/cases").json()[0]["id"] == case_id
    assert client.get(f"/api/cases/{case_id}/stats").json()["events"] == 0


def test_invalid_uploads_rejected(client):
    case_id = create_case(client)
    bad_extension = client.post(f"/api/cases/{case_id}/evidence",
                                files={"file": ("something.txt", b"hello")})
    assert bad_extension.status_code == 400
    bad_magic = client.post(f"/api/cases/{case_id}/evidence",
                            files={"file": ("sample.evtx", b"not a Windows log")})
    assert bad_magic.status_code == 400
    assert client.get(f"/api/cases/{case_id}/evidence").json() == []


def test_index_and_search_evidence(client, monkeypatch):
    import traceforge.app as app_module
    monkeypatch.setattr(app_module, "iter_evtx_records",
                        lambda path: iter([parse_event_xml(SAMPLE)]))
    case_id = create_case(client)
    response = client.post(f"/api/cases/{case_id}/evidence",
                           files={"file": ("Security.evtx", b"ElfFile\x00" + b"\x00" * 16)})
    assert response.status_code == 201, response.text
    evidence = response.json()
    assert evidence["status"] == "ready"
    assert len(evidence["sha256"]) == 64
    assert evidence["event_count"] == 1
    stats = client.get(f"/api/cases/{case_id}/stats").json()
    assert stats["events"] == 1
    assert stats["high"] == 1
    query = client.get(f"/api/cases/{case_id}/events?q=analyst").json()
    assert query["total"] == 1
    assert client.get(f"/api/cases/{case_id}/events?q=missing").json()["total"] == 0
    event_id = query["items"][0]["id"]
    detailed = client.get(f"/api/cases/{case_id}/events/{event_id}").json()
    assert detailed["raw_xml"].startswith("<Event")
    assert client.get(f"/api/cases/{case_id}/events?event_id=4624").json()["total"] == 0
    assert len(client.get(f"/api/cases/{case_id}/findings").json()) == 1
    report = client.get(f"/api/cases/{case_id}/report.md")
    assert evidence["sha256"] in report.text
    assert "Security audit log cleared" in report.text
    assert client.get(f"/api/cases/{case_id}/evidence").json()[0]["status"] == "ready"


def test_failed_parser_preserves_file_and_marks_failed(client, monkeypatch):
    import traceforge.app as app_module

    def broken(_path):
        raise ValueError("Corrupted EVTX structure")
        yield  # pragma: no cover

    monkeypatch.setattr(app_module, "iter_evtx_records", broken)
    case_id = create_case(client)
    response = client.post(f"/api/cases/{case_id}/evidence",
                           files={"file": ("bad.evtx", b"ElfFile\x00" + b"\x00" * 16)})
    assert response.status_code == 422
    evidence = client.get(f"/api/cases/{case_id}/evidence").json()
    assert evidence[0]["status"] == "failed"
    assert (Path(__import__("os").environ["TRACEFORGE_DATA_DIR"]) /
            "evidence" / (evidence[0]["id"] + ".evtx")).exists()


def test_no_chainsaw_configuration_is_explicit(client):
    status = client.get("/api/chainsaw/status").json()
    assert isinstance(status["available"], bool)
    assert status["configured"] is False
