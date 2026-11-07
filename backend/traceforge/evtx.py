"""EVTX extraction and a deliberately small normalization layer."""
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Iterator

EVENT_NAMES = {
    1: "Process created (Sysmon)", 3: "Network connection (Sysmon)",
    104: "Event log cleared", 4624: "Successful logon", 4625: "Failed logon",
    4688: "Process created", 4698: "Scheduled task created",
    4720: "User account created", 4728: "Member added to global group",
    4732: "Member added to local group", 7045: "Service installed",
    1102: "Security audit log cleared", 4104: "PowerShell script block",
}

# A match here is a triage observation, NOT proof of compromise.
TRIAGE_RULES = {
    1102: ("TF-1102", "Security audit log cleared", "high",
           "Investigate who cleared the Security log and why."),
    104: ("TF-0104", "Windows event log cleared", "medium",
          "A log was cleared. Verify whether this was authorized."),
    7045: ("TF-7045", "New service installed", "medium",
           "Review the service name, executable path, and installer."),
    4698: ("TF-4698", "Scheduled task created", "medium",
           "Review the task action, account, and creation context."),
    4720: ("TF-4720", "User account created", "medium",
           "Confirm that this new account was authorized."),
}


def _text(parent: ET.Element | None, tag: str) -> str:
    if parent is None:
        return ""
    found = parent.find("{*}" + tag)
    return (found.text or "").strip() if found is not None else ""


def parse_event_xml(xml: str) -> dict:
    """Normalize one Windows event while keeping its original XML."""
    root = ET.fromstring(xml)
    system = root.find("{*}System")
    if system is None:
        raise ValueError("Event is missing the System element")
    raw_id = _text(system, "EventID")
    try:
        event_id = int(raw_id)
    except ValueError:
        event_id = None
    provider = system.find("{*}Provider")
    time_created = system.find("{*}TimeCreated")
    data = {}
    event_data = root.find("{*}EventData")
    if event_data is not None:
        for element in event_data.findall("{*}Data"):
            key = element.attrib.get("Name") or "Data"
            value = (element.text or "").strip()
            if key in data:
                old = data[key]
                data[key] = old + [value] if isinstance(old, list) else [old, value]
            else:
                data[key] = value
    user_data = root.find("{*}UserData")
    if user_data is not None:
        for element in user_data.iter():
            if len(element) == 0 and (element.text or "").strip():
                data.setdefault(element.tag.split("}")[-1], element.text.strip())

    account = next(
        (str(data[key]) for key in ("TargetUserName", "SubjectUserName",
         "User", "AccountName") if data.get(key)), ""
    )
    label = EVENT_NAMES.get(event_id, "Windows event")
    summary = label + (" · " + account if account else "")
    return {
        "timestamp": time_created.attrib.get("SystemTime", "") if time_created is not None else "",
        "event_id": event_id,
        "record_id": _text(system, "EventRecordID"),
        "host": _text(system, "Computer"),
        "channel": _text(system, "Channel"),
        "provider": provider.attrib.get("Name", "") if provider is not None else "",
        "account": account,
        "summary": summary,
        "data": data,
        "raw_xml": xml,
    }


def iter_evtx_records(path: Path) -> Iterator[dict]:
    """Read native EVTX records via the optional-in-runtime python-evtx dependency."""
    from Evtx.Evtx import Evtx  # installed by requirements.txt
    with Evtx(str(path)) as log:
        for record in log.records():
            yield parse_event_xml(record.xml())
