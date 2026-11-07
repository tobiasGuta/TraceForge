"""TraceForge API and static web dashboard."""
from contextlib import asynccontextmanager
from pathlib import Path
from uuid import uuid4
import hashlib
import json
import os

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.responses import PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from .chainsaw import configuration, hunt
from .db import data_dir, database, initialize, now
from .evtx import TRIAGE_RULES, iter_evtx_records
from .processes import router as processes_router

MAX_UPLOAD_BYTES = 25 * 1024 * 1024
MAX_EVENTS_PER_FILE = 100_000


@asynccontextmanager
async def lifespan(_app: FastAPI):
    initialize()
    yield


app = FastAPI(title="TraceForge", version="0.2.0", lifespan=lifespan)
app.include_router(processes_router)


class CaseInput(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=1500)


def ensure_case(case_id: str) -> dict:
    with database() as db:
        row = db.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
    if row is None:
        raise HTTPException(404, "Case not found")
    return dict(row)


@app.get("/api/health")
def health():
    return {"status": "ok", "version": "0.2.0"}


@app.get("/api/cases")
def list_cases():
    with database() as db:
        rows = db.execute("""
            SELECT c.*, (SELECT COUNT(*) FROM evidence e WHERE e.case_id=c.id) evidence_count,
                (SELECT COUNT(*) FROM events v WHERE v.case_id=c.id) event_count,
                (SELECT COUNT(*) FROM findings f WHERE f.case_id=c.id) finding_count
            FROM cases c ORDER BY c.created_at DESC
        """).fetchall()
    return [dict(row) for row in rows]


@app.post("/api/cases", status_code=201)
def create_case(payload: CaseInput):
    name = payload.name.strip()
    if not name:
        raise HTTPException(422, "Case name cannot be blank")
    record = {"id": str(uuid4()), "name": name,
              "description": payload.description.strip(), "created_at": now()}
    with database() as db:
        db.execute("INSERT INTO cases(id,name,description,created_at) VALUES(?,?,?,?)",
                   tuple(record.values()))
    return record


@app.get("/api/cases/{case_id}")
def get_case(case_id: str):
    return ensure_case(case_id)


def _index_file(case_id: str, evidence_id: str, path: Path) -> int:
    count = 0
    try:
        with database() as db:
            for event in iter_evtx_records(path):
                if count >= MAX_EVENTS_PER_FILE:
                    raise ValueError("File exceeds the 100,000-event indexing limit")
                cursor = db.execute("""
                    INSERT INTO events(case_id,evidence_id,timestamp,event_id,record_id,host,
                        channel,provider,account,summary,data_json,raw_xml)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
                """, (case_id, evidence_id, event["timestamp"], event["event_id"],
                      event["record_id"], event["host"], event["channel"],
                      event["provider"], event["account"], event["summary"],
                      json.dumps(event["data"], ensure_ascii=False), event["raw_xml"]))
                rule = TRIAGE_RULES.get(event["event_id"])
                if rule:
                    rule_id, title, severity, explanation = rule
                    db.execute("""
                        INSERT INTO findings(case_id,evidence_id,event_row_id,rule_id,title,
                            severity,explanation,created_at)
                        VALUES(?,?,?,?,?,?,?,?)
                    """, (case_id, evidence_id, cursor.lastrowid, rule_id, title,
                          severity, explanation, now()))
                count += 1
            db.execute("UPDATE evidence SET status='ready', event_count=? WHERE id=?",
                       (count, evidence_id))
    except Exception as exc:
        with database() as db:
            db.execute("UPDATE evidence SET status='failed', error=? WHERE id=?",
                       (str(exc)[:300], evidence_id))
        raise
    return count


@app.post("/api/cases/{case_id}/evidence", status_code=201)
async def upload_evidence(case_id: str, file: UploadFile = File(...)):
    ensure_case(case_id)
    filename = Path(file.filename or "").name[:255]
    if not filename.lower().endswith(".evtx"):
        raise HTTPException(400, "Only .evtx uploads are supported in v0.1")
    evidence_id = str(uuid4())
    folder = data_dir() / "evidence"
    folder.mkdir(parents=True, exist_ok=True)
    destination = folder / (evidence_id + ".evtx")
    temporary = folder / (evidence_id + ".upload")
    digest = hashlib.sha256()
    total = 0
    try:
        with temporary.open("wb") as output:
            first = True
            while chunk := await file.read(1024 * 1024):
                if first:
                    first = False
                    if not chunk.startswith(b"ElfFile\x00"):
                        raise HTTPException(400, "Invalid EVTX file header")
                total += len(chunk)
                if total > MAX_UPLOAD_BYTES:
                    raise HTTPException(413, "EVTX file exceeds 25 MB upload limit")
                digest.update(chunk)
                output.write(chunk)
        if total == 0:
            raise HTTPException(400, "Empty file")
        os.replace(temporary, destination)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    finally:
        await file.close()

    record = {
        "id": evidence_id, "case_id": case_id, "filename": filename,
        "sha256": digest.hexdigest(), "size_bytes": total,
        "uploaded_at": now(), "status": "processing",
    }
    with database() as db:
        db.execute("""INSERT INTO evidence(id,case_id,filename,sha256,size_bytes,uploaded_at,status)
                      VALUES(?,?,?,?,?,?,?)""", tuple(record.values()))
    try:
        record["event_count"] = await run_in_threadpool(_index_file, case_id, evidence_id, destination)
        record["status"] = "ready"
    except Exception as exc:
        raise HTTPException(422, "Evidence preserved, but EVTX indexing failed: " + str(exc)[:200]) from exc
    return record


@app.get("/api/cases/{case_id}/evidence")
def list_evidence(case_id: str):
    ensure_case(case_id)
    with database() as db:
        rows = db.execute("""SELECT * FROM evidence WHERE case_id=? ORDER BY uploaded_at DESC""",
                          (case_id,)).fetchall()
    return [dict(row) for row in rows]


@app.get("/api/cases/{case_id}/field-keys")
def list_field_keys(case_id: str):
    """Discover actual EventData field names instead of assuming a sample schema."""
    ensure_case(case_id)
    with database() as db:
        rows = db.execute("""
            SELECT DISTINCT fields.key
            FROM events AS e, json_each(e.data_json) AS fields
            WHERE e.case_id=? AND fields.key IS NOT NULL
            ORDER BY fields.key LIMIT 300
        """, (case_id,)).fetchall()
    return [row["key"] for row in rows]


@app.get("/api/cases/{case_id}/hosts")
def list_hosts(case_id: str):
    ensure_case(case_id)
    with database() as db:
        rows = db.execute("""
            SELECT DISTINCT host FROM events
            WHERE case_id=? AND host != ''
            ORDER BY host LIMIT 300
        """, (case_id,)).fetchall()
    return [row["host"] for row in rows]


@app.get("/api/cases/{case_id}/events")
def list_events(case_id: str, q: str = Query(default="", max_length=200),
                event_id: int | None = None, page: int = Query(default=1, ge=1),
                limit: int = Query(default=50, ge=1, le=200),
                order: str = Query(default="desc", pattern="^(asc|desc)$"),
                host: str = Query(default="", max_length=255),
                field_key: str = Query(default="", max_length=200),
                field_value: str = Query(default="", max_length=250)):
    ensure_case(case_id)
    where = ["case_id = ?"]
    params: list = [case_id]
    if event_id is not None:
        where.append("event_id = ?")
        params.append(event_id)
    if host:
        where.append("host = ?")
        params.append(host)
    if field_value and not field_key:
        raise HTTPException(422, "Choose a field name when filtering by field value")
    if field_key:
        term = "%" + field_value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        where.append("""EXISTS(
            SELECT 1 FROM json_each(events.data_json) AS field
            WHERE field.key = ?
              AND CAST(field.value AS TEXT) LIKE ? ESCAPE '\'
        )""")
        params.extend([field_key, term])
    if q:
        where.append("""(summary LIKE ? OR host LIKE ? OR account LIKE ?
                        OR provider LIKE ? OR data_json LIKE ?)""")
        # Treat percent and underscore as literals to avoid surprising wildcard searches.
        term = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        where[-1] = where[-1].replace("LIKE ?", "LIKE ? ESCAPE '\\'")
        params.extend([term] * 5)
    condition = " AND ".join(where)
    with database() as db:
        count = db.execute("SELECT COUNT(*) FROM events WHERE " + condition, params).fetchone()[0]
        rows = db.execute("""
            SELECT id,evidence_id,timestamp,event_id,record_id,host,channel,provider,
                   account,summary,data_json FROM events WHERE """ + condition +
            " ORDER BY timestamp " + order.upper() + ", id " + order.upper() +
            " LIMIT ? OFFSET ?", (*params, limit, (page - 1) * limit)).fetchall()
    events = [{**dict(row), "data": json.loads(row["data_json"])} for row in rows]
    for item in events:
        item.pop("data_json")
    return {"total": count, "page": page, "limit": limit, "items": events}


@app.get("/api/cases/{case_id}/events/{event_row_id}")
def get_event(case_id: str, event_row_id: int):
    ensure_case(case_id)
    with database() as db:
        row = db.execute("SELECT * FROM events WHERE case_id=? AND id=?",
                         (case_id, event_row_id)).fetchone()
    if row is None:
        raise HTTPException(404, "Event not found")
    result = dict(row)
    result["data"] = json.loads(result.pop("data_json"))
    return result


@app.get("/api/cases/{case_id}/findings")
def list_findings(case_id: str):
    ensure_case(case_id)
    with database() as db:
        rows = db.execute("""
            SELECT f.*, e.timestamp, e.event_id, e.host, e.account, e.summary
            FROM findings f JOIN events e ON e.id=f.event_row_id
            WHERE f.case_id=?
            ORDER BY CASE f.severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END,
                     e.timestamp DESC LIMIT 500
        """, (case_id,)).fetchall()
    return [dict(row) for row in rows]


@app.get("/api/cases/{case_id}/stats")
def stats(case_id: str):
    ensure_case(case_id)
    with database() as db:
        events = db.execute("SELECT COUNT(*) FROM events WHERE case_id=?", (case_id,)).fetchone()[0]
        findings = db.execute("SELECT COUNT(*) FROM findings WHERE case_id=?", (case_id,)).fetchone()[0]
        evidence = db.execute("SELECT COUNT(*) FROM evidence WHERE case_id=?", (case_id,)).fetchone()[0]
        high = db.execute("""SELECT COUNT(*) FROM findings WHERE case_id=? AND severity='high'""",
                          (case_id,)).fetchone()[0]
        top = db.execute("""SELECT event_id,COUNT(*) as count FROM events
                            WHERE case_id=? GROUP BY event_id ORDER BY count DESC LIMIT 7""",
                         (case_id,)).fetchall()
        activity = db.execute("""SELECT substr(timestamp,1,13) as hour,COUNT(*) as count
                                 FROM events WHERE case_id=? AND timestamp IS NOT NULL
                                 AND timestamp != '' GROUP BY hour ORDER BY hour DESC LIMIT 24""",
                              (case_id,)).fetchall()
    return {"events": events, "evidence": evidence, "findings": findings,
            "high": high, "top_event_ids": [dict(x) for x in top],
            "activity": list(reversed([dict(x) for x in activity]))}


@app.get("/api/chainsaw/status")
def chainsaw_status():
    return configuration()


@app.post("/api/cases/{case_id}/hunt")
async def run_hunt(case_id: str):
    ensure_case(case_id)
    with database() as db:
        rows = db.execute("""SELECT id FROM evidence WHERE case_id=? AND status='ready'
                             ORDER BY uploaded_at LIMIT 25""", (case_id,)).fetchall()
    if not rows:
        raise HTTPException(400, "Upload and index an EVTX file first")
    paths = [data_dir() / "evidence" / (row["id"] + ".evtx") for row in rows]
    try:
        result = await run_in_threadpool(hunt, paths)
    except RuntimeError as exc:
        raise HTTPException(503, str(exc)) from exc
    hunt_record = {
        "id": str(uuid4()), "case_id": case_id, "created_at": now(),
        "status": "completed", "output_json": json.dumps(result, ensure_ascii=False),
        "stderr": result.get("stderr", ""),
    }
    with database() as db:
        db.execute("""INSERT INTO hunts(id,case_id,created_at,status,output_json,stderr)
                      VALUES(?,?,?,?,?,?)""", tuple(hunt_record.values()))
    return {**hunt_record, "output": result}


@app.get("/api/cases/{case_id}/hunts")
def list_hunts(case_id: str):
    ensure_case(case_id)
    with database() as db:
        rows = db.execute("""SELECT * FROM hunts WHERE case_id=? ORDER BY created_at DESC LIMIT 10""",
                          (case_id,)).fetchall()
    return [{**dict(row), "output": json.loads(row["output_json"])} for row in rows]


@app.get("/api/cases/{case_id}/report.md")
def report(case_id: str):
    case = ensure_case(case_id)
    evidence = list_evidence(case_id)
    findings = list_findings(case_id)
    lines = [
        "# TraceForge investigation report", "",
        "Case: " + case["name"], "Case ID: " + case_id,
        "Description: " + case["description"], "Generated (UTC): " + now(), "",
        "## Evidence inventory", "",
    ]
    if not evidence:
        lines.append("No evidence uploaded.")
    for item in evidence:
        lines += [
            "- File: " + item["filename"],
            "  - Evidence ID: " + item["id"],
            "  - SHA-256: " + item["sha256"],
            "  - Size (bytes): " + str(item["size_bytes"]),
            "  - Status: " + item["status"],
            "  - Indexed events: " + str(item["event_count"]),
        ]
    lines += ["", "## Triage observations", "",
              "Rule matches are leads for analyst verification, not confirmed incidents.", ""]
    if not findings:
        lines.append("No built-in triage observations.")
    for item in findings:
        lines += [
            "### " + item["title"],
            "- Severity: " + item["severity"],
            "- Rule: " + item["rule_id"],
            "- Event row: " + str(item["event_row_id"]),
            "- Evidence ID: " + item["evidence_id"],
            "- Timestamp: " + str(item["timestamp"]),
            "- Host: " + str(item["host"]),
            "- Rationale: " + item["explanation"], "",
        ]
    lines += ["", "## Methodology", "",
              "Original uploaded bytes are preserved; SHA-256 is calculated at upload. "
              "Built-in triage matches inspect Windows Event IDs. Chainsaw output, when "
              "configured, is stored separately and should be reviewed independently.", ""]
    return PlainTextResponse(
        "\n".join(lines),
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="traceforge-report.md"'},
    )


# Register API routes before the catch-all static mount.
FRONTEND = Path(__file__).resolve().parents[2] / "frontend"
if FRONTEND.is_dir():
    app.mount("/", StaticFiles(directory=str(FRONTEND), html=True), name="ui")
