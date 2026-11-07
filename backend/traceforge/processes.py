"""Source-aware process exploration and conservative forensic event correlation.

This module understands documented Windows Security 4688 and Sysmon Event 1
fields. It never hardcodes sample machines, process names, accounts or attacks.
Relationships derived from PIDs are *candidates* because PIDs are reused.
"""
from datetime import datetime, timedelta, timezone
import json
import sqlite3

from fastapi import APIRouter, HTTPException, Query

from .db import database

router = APIRouter()

# Provider guards avoid treating arbitrary Event ID 1 records as Sysmon processes.
PROCESS_SQL = """(
    (event_id = 4688 AND provider LIKE '%Security-Auditing%')
    OR (event_id = 1 AND provider LIKE '%Sysmon%')
)"""
SELECT_PROCESS = """id,case_id,evidence_id,timestamp,event_id,record_id,
                    host,channel,provider,account,summary,data_json"""
MAX_CONTEXT_PROCESSES = 10000
MAX_NEARBY_EVENTS = 100


def _case_exists(db: sqlite3.Connection, case_id: str):
    if not db.execute("SELECT 1 FROM cases WHERE id=?", (case_id,)).fetchone():
        raise HTTPException(404, "Case not found")


def _process(event: dict) -> dict:
    payload = json.loads(event.pop("data_json"))
    # A process-create schema is recognized by provider + Event ID, not names.
    sysmon = event["event_id"] == 1 and "sysmon" in (event["provider"] or "").lower()
    values = payload
    def pick(*keys):
        for key in keys:
            value = values.get(key)
            if value is not None and str(value).strip():
                return str(value)
        return ""
    return {
        **event,
        "image": pick("Image") if sysmon else pick("NewProcessName"),
        "command_line": pick("CommandLine"),
        "parent_image": pick("ParentImage") if sysmon else pick("ParentProcessName"),
        "pid": pick("ProcessId") if sysmon else pick("NewProcessId"),
        "parent_pid": pick("ParentProcessId") if sysmon else pick("ProcessId"),
        "process_guid": pick("ProcessGuid") if sysmon else "",
        "parent_guid": pick("ParentProcessGuid") if sysmon else "",
        "source": "sysmon" if sysmon else "windows-security",
        "data": payload,
    }


def _when(timestamp: str | None):
    try:
        if not timestamp:
            return None
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        if not parsed.tzinfo:
            # The source does not indicate an offset: avoid temporal correlation.
            return None
        return parsed.astimezone(timezone.utc)
    except ValueError:
        return None


def _pid(value: str) -> int | None:
    try:
        if not value:
            return None
        # Windows Security 4688 often uses hex; Sysmon typically uses decimal.
        number = int(value.strip(), 16) if value.strip().lower().startswith("0x") else int(value.strip(), 10)
        return number if number >= 0 else None
    except ValueError:
        return None


def _norm_path(value: str) -> str:
    return value.replace("/", "\\").strip().casefold() if value else ""


def _same_process_parent(parent: dict, child: dict) -> tuple[str, str] | None:
    """Return confidence + reason; never assert PID-only matches as confirmed."""
    if parent["id"] == child["id"]:
        return None
    if not parent["host"] or parent["host"].casefold() != (child["host"] or "").casefold():
        return None
    start, end = _when(parent["timestamp"]), _when(child["timestamp"])
    if start is None or end is None or not (start <= end <= start + timedelta(hours=24)):
        return None
    if parent["process_guid"] and child["parent_guid"]:
        if parent["process_guid"].casefold() == child["parent_guid"].casefold():
            return ("source-guid", "Matching Sysmon ProcessGuid/ParentProcessGuid on the same host.")
        return None
    ppid, pid = _pid(child["parent_pid"]), _pid(parent["pid"])
    if ppid is None or pid is None or ppid != pid:
        return None
    # If the child supplies an expected parent image, disagreement rejects the candidate.
    if child["parent_image"] and parent["image"] and _norm_path(child["parent_image"]) != _norm_path(parent["image"]):
        return None
    return ("pid-candidate", "Matching parent PID on this host within 24 hours; PID reuse is possible.")


def _candidate(row: dict, confidence: str, reason: str) -> dict:
    return {
        "id": row["id"], "event_id": row["event_id"], "timestamp": row["timestamp"],
        "host": row["host"], "image": row["image"], "command_line": row["command_line"],
        "pid": row["pid"], "parent_pid": row["parent_pid"], "confidence": confidence,
        "reason": reason,
    }


@router.get("/api/cases/{case_id}/processes")
def list_processes(
    case_id: str,
    q: str = Query(default="", max_length=200),
    host: str = Query(default="", max_length=255),
    page: int = Query(default=1, ge=1, le=10000),
    limit: int = Query(default=50, ge=1, le=200),
    order: str = Query(default="desc", pattern="^(asc|desc)$"),
):
    """Process-create events with searchable metadata; reads existing indexed EVTX events."""
    where = ["case_id=?", PROCESS_SQL]
    args: list = [case_id]
    if host:
        where.append("host=?")
        args.append(host)
    if q:
        term = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        # Searches process image, command, parent image, PID, host, account.
        where.append("""(
            host LIKE ? ESCAPE '\\'
            OR account LIKE ? ESCAPE '\\'
            OR json_extract(data_json, '$.NewProcessName') LIKE ? ESCAPE '\\'
            OR json_extract(data_json, '$.Image') LIKE ? ESCAPE '\\'
            OR json_extract(data_json, '$.CommandLine') LIKE ? ESCAPE '\\'
            OR json_extract(data_json, '$.ParentProcessName') LIKE ? ESCAPE '\\'
            OR json_extract(data_json, '$.ParentImage') LIKE ? ESCAPE '\\'
            OR json_extract(data_json, '$.NewProcessId') LIKE ? ESCAPE '\\'
            OR json_extract(data_json, '$.ProcessId') LIKE ? ESCAPE '\\'
        )""")
        args.extend([term] * 9)
    clause = " AND ".join(where)
    sort = order.upper()
    with database() as db:
        _case_exists(db, case_id)
        total = db.execute("SELECT COUNT(*) FROM events WHERE " + clause, args).fetchone()[0]
        rows = db.execute(
            "SELECT " + SELECT_PROCESS + " FROM events WHERE " + clause +
            " ORDER BY timestamp " + sort + ", id " + sort + " LIMIT ? OFFSET ?",
            (*args, limit, (page-1)*limit),
        ).fetchall()
        hosts = db.execute(
            "SELECT DISTINCT host FROM events WHERE case_id=? AND " + PROCESS_SQL +
            " AND host != '' ORDER BY host LIMIT 200", (case_id,)
        ).fetchall()
    return {
        "total": total, "page": page, "limit": limit,
        "hosts": [row["host"] for row in hosts],
        "items": [_process(dict(row)) for row in rows],
    }


@router.get("/api/cases/{case_id}/events/{event_row_id}/context")
def event_context(
    case_id: str,
    event_row_id: int,
    window_minutes: int = Query(default=10, ge=1, le=1440),
    limit: int = Query(default=50, ge=1, le=MAX_NEARBY_EVENTS),
):
    """Nearby activity plus conservatively labeled parent/child process candidates.

    No cross-host pivots, inferred attacks, or unbounded raw event responses.
    """
    with database() as db:
        _case_exists(db, case_id)
        focal = db.execute(
            "SELECT " + SELECT_PROCESS + " FROM events WHERE case_id=? AND id=?",
            (case_id, event_row_id),
        ).fetchone()
        if focal is None:
            raise HTTPException(404, "Event not found")
        event = dict(focal)
        timestamp = _when(event["timestamp"])
        host = event["host"]
        if not timestamp or not host:
            return {
                "focal_event_id": event_row_id,
                "nearby": [], "parents": [], "children": [],
                "note": "Missing timestamp with timezone or host; correlation unavailable.",
                "truncated": False,
            }
        before, after = timestamp - timedelta(minutes=window_minutes), timestamp + timedelta(minutes=window_minutes)
        # Intersect on same host and UTC time, not lexicographical timestamp strings.
        nearby = db.execute(
            """SELECT id,evidence_id,timestamp,event_id,record_id,host,channel,
                      provider,account,summary,data_json
               FROM events
               WHERE case_id=? AND host=? AND id != ?
                 AND julianday(timestamp) BETWEEN julianday(?) AND julianday(?)
               ORDER BY ABS(julianday(timestamp) - julianday(?)), id LIMIT ?""",
            (case_id, host, event_row_id, before.isoformat(), after.isoformat(),
             timestamp.isoformat(), limit),
        ).fetchall()
        related = [{
            **{key: row[key] for key in
               ("id", "evidence_id", "timestamp", "event_id", "record_id", "host", "channel",
                "provider", "account", "summary")},
            "data": json.loads(row["data_json"]),
        } for row in nearby]
        # Pull creation records within 24 hours on the same host. There is a
        # hard cap, and truncation is shown rather than implying full coverage.
        earliest = timestamp - timedelta(hours=24)
        latest = timestamp + timedelta(hours=24)
        candidate_rows = db.execute(
            "SELECT " + SELECT_PROCESS + " FROM events WHERE case_id=? AND host=? AND " +
            PROCESS_SQL +
            " AND julianday(timestamp) BETWEEN julianday(?) AND julianday(?) " +
            "ORDER BY timestamp, id LIMIT ?",
            (case_id, host, earliest.isoformat(), latest.isoformat(), MAX_CONTEXT_PROCESSES + 1),
        ).fetchall()

    processes = [_process(dict(row)) for row in candidate_rows[:MAX_CONTEXT_PROCESSES]]
    truncated = len(candidate_rows) > MAX_CONTEXT_PROCESSES
    # Correlation applies only when the focal record is a recognized process creation.
    can_correlate = (
        (event["event_id"] == 4688 and "security-auditing" in (event["provider"] or "").lower())
        or (event["event_id"] == 1 and "sysmon" in (event["provider"] or "").lower())
    )
    parents, children = [], []
    if can_correlate:
        focus = _process(event)
        for other in processes:
            link = _same_process_parent(other, focus)
            if link:
                parents.append(_candidate(other, *link))
            reverse = _same_process_parent(focus, other)
            if reverse:
                children.append(_candidate(other, *reverse))
        # Most recent parent candidates first; do not hide ambiguity.
        parents.sort(key=lambda item: item["timestamp"] or "", reverse=True)
        children.sort(key=lambda item: item["timestamp"] or "")
    note = (
        "Same-host nearby events are temporal context, not proof of causality. "
        "GUID relationships use Sysmon process GUIDs; PID relationships are candidates "
        "because PID reuse is possible. Correlation is restricted to a 24-hour window."
    ) if can_correlate else (
        "The selected event is not a recognized process creation. Showing only "
        "same-host events in the selected time window."
    )
    if truncated:
        note += " Process candidate scan was capped at 10,000 records; results may be incomplete."
    return {
        "focal_event_id": event_row_id, "host": host,
        "window_minutes": window_minutes, "nearby": related,
        "parents": parents[:20], "children": children[:100],
        "parent_total": len(parents), "child_total": len(children),
        "note": note, "truncated": truncated,
    }
