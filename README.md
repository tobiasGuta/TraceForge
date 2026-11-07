# TraceForge

**TraceForge is a local-first, self-hosted Windows event-log investigation dashboard.** Preserve native EVTX files, index their events, find triage leads, explore timelines, and export evidence-linked case reports. Optionally run [WithSecure Chainsaw](https://github.com/WithSecureOpenSource/chainsaw) with your own rule packs.

> **Status: v0.2.0 MVP.** A usable starting point for individual analysts and DFIR labs, not a production-grade multi-user SOC platform. No authentication is implemented: **do not expose this deployment to the public internet.**

## Features

- Responsive, build-free, themeable web dashboard with seven investigative views
- Create cases and upload native Windows `.evtx` files (25 MB per upload)
- Preserve original uploaded bytes under generated IDs, compute SHA-256 at ingestion
- Normalize Windows event metadata while retaining original record XML
- Search Event IDs, host, provider, account, and payload; filter by actual EventData field names and values, with source-linked inspection
- Chronological timeline, event-frequency charts, built-in triage findings
- Search Windows Security (4688) and Sysmon (1) process-creation events without rebuilding existing case data
- Pivot from any event to same-host nearby events and conservative process parent/child candidates
- Export an investigation report as Markdown with evidence IDs and hashes
- Optional Chainsaw hunting; stores its **raw JSON output** for review (not falsely mapped to internal findings)
- Single Docker service, SQLite database, persistent evidence volume, non-root container
- Python tests and GitHub Actions CI

### Screens and workflows

| View | Purpose |
| --- | --- |
| Overview | Case metrics, activity chart, frequent event IDs, latest findings |
| Event explorer | Text, host, Event ID and dynamic EventData field filters; source-linked records |
| Process explorer | Cross-host executable, command-line, PID and account search for supported process-create events |
| Timeline | Chronological view of up to the first 200 indexed events |
| Findings | Clearly labeled **triage** observations, linked back to records |
| Evidence vault | Source filename, size, upload status, SHA-256 fingerprint |
| Chainsaw engine | Configuration status, optional on-demand hunting, raw results |

## Appearance and event inspection

The dashboard now provides an **Appearance** panel in the top bar:

- Switch between **dark**, **light**, or **system-matched** mode. Use the adjacent quick-toggle to swap light and dark instantly.
- Start from four coordinated palettes: **Atlas blue**, **Forest**, **Orchid**, and **Ember**.
- Edit **11 independent colors**: page background, sidebar, cards, raised surfaces, borders, primary/secondary text, accent, success, warning and danger.
- Watch changes live; a contrast indicator warns when panel text falls below a 4.5:1 ratio.
- Settings for light and dark modes are stored separately in the browser's `localStorage`. They survive refreshes but are **not** shared across browsers or users. **Reset current mode** restores the default colors for the active mode.

Clicking an event now opens a **full-screen forensic workspace** instead of a side drawer. The Overview tab shows process lineage, execution details, and a dedicated evidence-provenance column using readable label/value rows rather than clusters of small cards. Large **All fields**, **JSON**, and **Original XML** views use the available screen width; JSON and XML support line wrapping and copying. Use **Back to events** or Escape to return. Event 4688 rows also show the process basename and command-line preview in the explorer. Your saved appearance palette is retained.

## Process exploration and evidence correlation (v0.2)

Select **Process explorer** in the sidebar to search process creation records from any indexed Windows Security Event 4688 or Sysmon Event 1 log. Search executable paths, command lines, account names, hostnames or PIDs, and filter by machine. Results are generated from the actual evidence; there are no preprogrammed names, flags, hostnames or suspect processes. Your already uploaded evidence is searchable immediately—no re-upload or database migration is required.

The full-screen event inspector includes **Related activity**, which shows:

- Nearby same-host events within a ±10-minute window, clearly marked as temporal context, **not causation**.
- Matching Sysmon `ProcessGuid` / `ParentProcessGuid` relationships, when those GUIDs were recorded.
- **Potential**, not confirmed, parent/child relationships inferred from Security 4688 or Sysmon PIDs, with host, timing and reported parent-image checks. PIDs are routinely reused. PID-only links can be ambiguous.
- A note when parent evidence is missing, correlation is unsupported, or candidate scanning reaches its safety limit.

Cross-source schema support is intentionally conservative: a process must have a supported provider and event ID; no parent is fabricated just because its image name appears in the child record. The candidate window is limited to 24 hours and the correlation scan to 10,000 process records on the same host. Both bounds can omit legitimate long-running parent processes. This first version is **investigation assistance, not a complete EDR-grade process tree**.

**Event explorer** also has advanced filters populated from field names actually found in that case's EventData objects. You can pivot on unusual or vendor-specific fields without hardcoding a fixed set of keys.

API endpoints:
- `GET /api/cases/{case_id}/processes?q=&host=&page=&limit=&order=`
- `GET /api/cases/{case_id}/events/{row_id}/context?window_minutes=&limit=`
- `GET /api/cases/{case_id}/field-keys` and `GET /api/cases/{case_id}/hosts`
- Existing `GET /api/cases/{case_id}/events` accepts `host`, `field_key`, and `field_value`.

## Quick start (Docker)

Prerequisite: Docker and the Compose plugin.

```bash
git clone https://github.com/tobiasGuta/TraceForge.git
cd TraceForge
docker compose up --build -d
```

Open **http://127.0.0.1:8080**. Create a case, then upload an EVTX file.

To stop the app:

```bash
docker compose down
```

Uploaded evidence and SQLite data live in the named `traceforge-data` volume. `docker compose down -v` **deletes that data**.

The Compose port is intentionally bound to `127.0.0.1`. Do not change this to `0.0.0.0` or deploy it publicly without implementing authentication, HTTPS, access controls, and a hardened upload-processing boundary.

## Local development

Requires Python 3.11+.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
uvicorn traceforge.app:app --app-dir backend --reload --host 127.0.0.1 --port 8000
```

Visit **http://127.0.0.1:8000**. The frontend is plain HTML/CSS/JavaScript, deliberately without a Node build step. The initial MVP optimizes for auditability and easy self-hosting. A React/TypeScript migration is possible later.

Run tests:

```bash
pytest -q
node --check frontend/app.js
```

## Optional Chainsaw integration

TraceForge does **not** ship, auto-download, or modify Chainsaw, Sigma rules, or rule packs. To enable it in a local development shell, install a Chainsaw executable yourself and configure at least one supported rule source:

```bash
export CHAINSAW_BIN=/absolute/path/to/chainsaw
export CHAINSAW_RULES_DIR=/absolute/path/to/chainsaw-rules
# OR use Sigma:
export SIGMA_RULES_DIR=/absolute/path/to/sigma/rules
export CHAINSAW_MAPPING_FILE=/absolute/path/to/chainsaw/mappings/sigma-event-logs-all.yml
```

For Docker, bind-mount the executable **and any runtime dependencies** plus rules directories as read-only volumes, and set these environment variables in a Compose override. The default image intentionally does **not** include Chainsaw.

When configured, use **Chainsaw engine → Run Chainsaw hunt**. The backend executes `chainsaw hunt` with `--json -q` and configured `-r` / `-s --mapping` arguments; it does not invoke a shell. JSON is kept as returned because different rule collections/Chainsaw versions may emit different shapes. A run is bounded to 120 seconds, 25 evidence files, and 8 MB of result text. Carefully assess the binary and rule sources before enabling this feature.

## Built-in detection notes

The lightweight initial triage layer flags event IDs 1102 (Security log cleared), 104 (log cleared), 7045 (service installed), 4698 (scheduled task created), and 4720 (account created). **These events are not inherently malicious.** They are intentionally named triage leads, not malicious-activity verdicts.

Event ID 4104 (PowerShell script block) and 4624 (successful logon) are **not** treated as attacks by themselves. For accurate detections, bring Chainsaw and well-maintained Sigma rules and validate the supporting source records.

## Evidence model and limits

- Original bytes are written to a private storage directory using generated UUID filenames.
- SHA-256 is calculated during upload; source records retain their XML. Timestamps are preserved from the source log and displayed in the viewer's locale.
- Indexed event metadata and original record XML live in SQLite. File indexing is atomic at the database transaction level: a failed parse is recorded, but does not leave partially indexed events.
- Upload limit: **25 MB/file**. Indexing limit: **100,000 events/file**.
- Search currently uses SQLite `LIKE`, not a full-text index. Timeline shows the **earliest 200 events**, not a complete large-case correlation engine.
- Failed uploads with a valid EVTX header remain in the evidence vault with `failed` status for investigation.
- Reports capture the case, stored SHA-256 values, and linked built-in findings; analyst notes, full custody attestations, and Chainsaw findings normalization are future work.

## Architecture

```text
Browser (localhost only)
       |
FastAPI serves UI + JSON API
       |
       +-- SQLite (cases, evidence, events, findings, hunt runs)
       +-- Evidence store (original .evtx, SHA-256)
       +-- python-evtx parser
       +-- [optional] external Chainsaw executable + user-provided rules
```

Project layout:

```text
backend/traceforge/   FastAPI app, database, EVTX parser, Chainsaw adapter
frontend/             Build-free dashboard UI
tests/                API and parser tests
compose.yaml          Loopback-only local deployment
.github/workflows/    Continuous integration checks
```

## Security and scope

This MVP is for **local, trusted-user analysis**. The FastAPI app has no authentication or per-case authorization. Forensic files should be considered hostile input; the parser runs in a non-root container, but the system does not yet provide a dedicated hardened or sandboxed parsing worker. Never upload secrets to a public deployment. Consult [SECURITY.md](SECURITY.md) before deploying beyond your own machine.

## Roadmap

1. **v0.2:** asynchronous jobs, progress reporting, stronger isolation, robust pagination and indexed search
2. **v0.3:** normalized Chainsaw/Sigma findings with rule provenance and linked evidence; reproducible exports
3. **v0.4:** analyst notes, case history, MITRE ATT&CK mappings and correlation
4. **Later:** collaborative RBAC, audit trail, enterprise stores and optional local AI grounded in event citations

Contributions, security hardening, tests with real EVTX samples, and UX improvements are welcome.

## License and acknowledgments

TraceForge original source code is licensed under **MIT** (see [LICENSE](LICENSE)). Chainsaw is a separate third-party project licensed under GPL-3.0; it is **not bundled** in this repository. Any Sigma rules or externally installed tooling retain their own licenses. See the original [Chainsaw repository](https://github.com/WithSecureOpenSource/chainsaw) for details.
