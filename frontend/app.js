/* TraceForge build-free dashboard. All API-derived values are escaped before HTML rendering. */
'use strict';

const state = { cases: [], caseId: null, view: 'overview', page: 1, query: '',
                eventId: '', order: 'desc', renderToken: 0 };
const content = document.getElementById('content');
const labels = {
  overview: 'Overview', events: 'Event explorer', timeline: 'Timeline',
  findings: 'Findings', evidence: 'Evidence vault', chainsaw: 'Chainsaw engine'
};
const esc = (value) => String(value == null ? '' : value).replace(/[&<>"']/g, (char) =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]);
const formatTime = (s) => {
  if (!s) return 'Unknown time';
  const d = new Date(s);
  return Number.isNaN(d.valueOf()) ? String(s) : d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
};
const num = (n) => Number(n || 0).toLocaleString();
const currentCase = () => state.cases.find((c) => c.id === state.caseId);
const caseUrl = (part) => '/api/cases/' + encodeURIComponent(state.caseId) + (part || '');

async function api(path, options) {
  const response = await fetch(path, options);
  if (!response.ok) {
    let message = 'Request failed (' + response.status + ')';
    try {
      const data = await response.json();
      message = typeof data.detail === 'string' ? data.detail : message;
    } catch (_) {}
    throw new Error(message);
  }
  return response.json();
}
let toastTimer;
function notify(message, error) {
  const toast = document.getElementById('toast');
  toast.textContent = message;
  toast.className = 'toast visible' + (error ? ' toast-error' : '');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { toast.className = 'toast'; }, 5000);
}
function showDialog(id) { document.getElementById(id).showModal(); }
function closeDialogs() { document.querySelectorAll('dialog[open]').forEach((dialog) => dialog.close()); }

async function loadCases() {
  state.cases = await api('/api/cases');
  if (!state.cases.some((item) => item.id === state.caseId)) {
    state.caseId = state.cases[0]?.id || null;
  }
  const picker = document.getElementById('casePicker');
  picker.innerHTML = state.cases.length
    ? state.cases.map((c) => '<option value="' + esc(c.id) + '">' + esc(c.name) + '</option>').join('')
    : '<option value="">No cases yet</option>';
  picker.value = state.caseId || '';
  document.getElementById('uploadTop').hidden = !state.caseId;
}
function skeleton() {
  return '<div class="loading-state"><span class="spinner"></span><p>Loading case data…</p></div>';
}
function empty(title, description, actionHtml) {
  return '<div class="empty-state"><div class="empty-glyph">⌁</div><h3>' + esc(title) +
    '</h3><p>' + esc(description) + '</p>' + (actionHtml || '') + '</div>';
}
function pill(text, className) {
  return '<span class="pill ' + esc(className || '') + '">' + esc(text) + '</span>';
}
function titleBlock(kicker, title, subtitle, actions) {
  return '<div class="view-heading"><div><div class="eyebrow">' + esc(kicker) +
    '</div><h1>' + esc(title) + '</h1><p>' + esc(subtitle) + '</p></div>' +
    '<div class="heading-actions">' + (actions || '') + '</div></div>';
}
function statCard(label, value, symbol, hint, accent) {
  return '<div class="metric-card"><div class="metric-top"><span>' + esc(label) +
    '</span><span class="metric-symbol ' + (accent || '') + '">' + symbol +
    '</span></div><div class="metric-value">' + num(value) +
    '</div><div class="metric-hint">' + esc(hint) + '</div></div>';
}
function activityChart(rows) {
  if (!rows.length) return empty('No activity yet', 'Upload an EVTX file to visualize event activity.');
  const max = Math.max(...rows.map((r) => r.count), 1);
  const bars = rows.map((r) => {
    const percent = Math.max(6, Math.round(100 * r.count / max));
    const when = r.hour ? r.hour.replace('T', ' ') : '?';
    return '<div class="bar-col" title="' + esc(when + ': ' + r.count + ' events') +
      '"><div class="bar-fill" style="height:' + percent + '%"></div><span>' +
      esc(when.slice(-5)) + '</span></div>';
  }).join('');
  return '<div class="bar-chart" aria-label="Events grouped by hour">' + bars + '</div>';
}
function findingRow(f) {
  return '<button class="finding-row" data-action="event" data-id="' + f.event_row_id +
    '"><span class="severity-indicator ' + esc(f.severity) + '"></span>' +
    '<span class="finding-info"><strong>' + esc(f.title) + '</strong><small>' +
    esc(f.host || 'Unknown host') + ' · Event ' + esc(f.event_id) + ' · ' +
    esc(formatTime(f.timestamp)) + '</small></span>' + pill(f.severity, f.severity) +
    '<span class="row-chevron">›</span></button>';
}
function evidenceRow(e) {
  return '<div class="evidence-row"><div class="file-icon">EVTX</div><div class="file-info"><strong>' +
    esc(e.filename) + '</strong><small>' + esc(num(e.size_bytes)) +
    ' bytes · ' + esc(formatTime(e.uploaded_at)) + '</small><code class="hash">' +
    esc(e.sha256) + '</code></div><div class="file-side">' +
    pill(e.status, e.status === 'ready' ? 'ready' : e.status === 'failed' ? 'high' : '') +
    '<small>' + num(e.event_count) + ' events</small></div></div>' +
    (e.error ? '<div class="file-error">' + esc(e.error) + '</div>' : '');
}
function eventRow(e) {
  const process=e.data?.NewProcessName||e.data?.Image;
  const detail=e.data?.CommandLine||e.provider||e.channel||'Windows event';
  const observation=process?basename(process)+' · '+e.summary:e.summary;
  return '<tr class="event-row" data-action="event" data-id="' + e.id +
    '" tabindex="0" role="button" aria-label="Open event ' + esc(e.event_id) + '">' +
    '<td class="mono">' + esc(formatTime(e.timestamp)) + '</td>' +
    '<td>' + pill(e.event_id == null ? '—' : e.event_id, 'neutral') + '</td>' +
    '<td><strong>' + esc(observation) + '</strong><small title="' + esc(detail) + '">' + esc(detail) + '</small></td>' +
    '<td class="mono">' + esc(e.host || '—') + '</td>' +
    '<td class="mono">' + esc(e.account || '—') + '</td>' +
    '<td class="row-chevron">›</td></tr>';
}

async function renderOverview() {
  const [stats, findings, evidence, recent] = await Promise.all([
    api(caseUrl('/stats')), api(caseUrl('/findings')),
    api(caseUrl('/evidence')), api(caseUrl('/events?limit=5'))
  ]);
  const buttons = '<button class="button button-primary" data-action="upload">⇧ Upload EVTX</button>' +
    '<a class="button button-outline" href="' + caseUrl('/report.md') + '">↓ Export report</a>';
  let html = titleBlock('CASE OVERVIEW', currentCase().name,
    currentCase().description || 'Your forensic investigation at a glance.', buttons);
  html += '<div class="metrics">' +
    statCard('Indexed events', stats.events, '▤', 'Searchable forensic records') +
    statCard('Evidence files', stats.evidence, '◈', 'Original files preserved') +
    statCard('Triage findings', stats.findings, '◇', 'Observations to validate') +
    statCard('High-priority', stats.high, '!', 'Require analyst review', 'danger') + '</div>';
  html += '<div class="dashboard-grid"><section class="panel"><div class="panel-heading"><div><h2>Event activity</h2><p>Events grouped by UTC hour</p></div>' +
    pill('LAST 24 HOURS WITH DATA', 'neutral') + '</div>' + activityChart(stats.activity) + '</section>' +
    '<section class="panel"><div class="panel-heading"><div><h2>Top event IDs</h2><p>Most frequent in this case</p></div></div>';
  html += stats.top_event_ids.length ?
    '<div class="event-distribution">' + stats.top_event_ids.map((r) =>
      '<div class="distribution-row"><span class="mono">ID ' + esc(r.event_id ?? '—') +
      '</span><span class="distribution-track"><span style="width:' +
      Math.max(3, Math.round(r.count * 100 / stats.top_event_ids[0].count)) +
      '%"></span></span><strong>' + num(r.count) + '</strong></div>').join('') + '</div>' :
    '<p class="panel-placeholder">No indexed events.</p>';
  html += '</section></div>';
  html += '<div class="dashboard-grid"><section class="panel"><div class="panel-heading"><div><h2>Priority findings</h2><p>Built-in triage rules</p></div><button class="text-link" data-view="findings">View all ›</button></div>' +
    (findings.length ? findings.slice(0, 4).map(findingRow).join('') :
      '<p class="panel-placeholder">No findings yet. This does not guarantee the host is clean.</p>') +
    '</section><section class="panel"><div class="panel-heading"><div><h2>Recent evidence</h2><p>Integrity hashes and indexing status</p></div><button class="text-link" data-view="evidence">View vault ›</button></div>' +
    (evidence.length ? evidence.slice(0, 3).map(evidenceRow).join('') :
      '<p class="panel-placeholder">No evidence uploaded yet.</p>') + '</section></div>';
  html += '<section class="panel"><div class="panel-heading"><div><h2>Recent events</h2><p>Open an event to inspect its source record</p></div><button class="text-link" data-view="events">Explore events ›</button></div>' +
    (recent.items.length ? eventTable(recent.items) : '<p class="panel-placeholder">Your event stream will appear here.</p>') + '</section>';
  return html;
}
function eventTable(items) {
  return '<div class="table-scroll"><table class="events-table"><thead><tr><th>Timestamp</th><th>Event ID</th><th>Observation</th><th>Host</th><th>Account</th><th></th></tr></thead><tbody>' +
    items.map(eventRow).join('') + '</tbody></table></div>';
}
async function renderEvents() {
  const params = new URLSearchParams({ q: state.query, page: String(state.page),
    limit: '50', order: state.order });
  if (state.eventId) params.set('event_id', state.eventId);
  const result = await api(caseUrl('/events?' + params));
  let html = titleBlock('SEARCH & FILTER', 'Event explorer',
    'Search normalized event fields without losing the underlying XML.');
  html += '<div class="panel"><div class="filter-bar"><label class="filter-label">Text search<input id="eventSearch" placeholder="Username, process, host, command…" value="' +
    esc(state.query) + '"></label><label class="filter-label filter-small">Event ID<input id="eventIdFilter" type="number" min="0" placeholder="e.g. 4624" value="' +
    esc(state.eventId) + '"></label><label class="filter-label filter-small">Sort<select id="eventOrder"><option value="desc"' +
    (state.order === 'desc' ? ' selected' : '') + '>Newest first</option><option value="asc"' +
    (state.order === 'asc' ? ' selected' : '') + '>Oldest first</option></select></label>' +
    '<button class="button button-primary" data-action="filter">Search</button></div>' +
    '<div class="results-line"><b>' + num(result.total) + '</b> matching events</div>' +
    (result.items.length ? eventTable(result.items) :
      empty('No matching events', 'Try a different query or upload more EVTX evidence.')) +
    '<div class="pagination"><span>Page ' + state.page + ' of ' +
    Math.max(1, Math.ceil(result.total / 50)) + '</span><div>' +
    '<button class="button button-outline button-sm" data-action="previous" ' +
    (state.page === 1 ? 'disabled' : '') + '>Previous</button> ' +
    '<button class="button button-outline button-sm" data-action="next" ' +
    (state.page * 50 >= result.total ? 'disabled' : '') + '>Next</button></div></div></div>';
  return html;
}
async function renderTimeline() {
  const result = await api(caseUrl('/events?order=asc&limit=200'));
  let html = titleBlock('CHRONOLOGICAL VIEW', 'Investigation timeline',
    'Earliest 200 indexed records, ordered by source timestamp. Events are observations, not attack conclusions.');
  if (!result.items.length) return html + empty('No timeline yet', 'Upload a Windows event log to reconstruct activity.');
  html += '<div class="timeline"><div class="timeline-caption">Showing ' + num(result.items.length) +
    ' of ' + num(result.total) + ' records · timestamps may originate in different source time zones</div>';
  html += result.items.map((e) => '<button class="timeline-item" data-action="event" data-id="' +
    e.id + '"><span class="timeline-marker"></span><span class="timeline-time">' +
    esc(formatTime(e.timestamp)) + '</span><span class="timeline-body"><strong>' +
    esc(e.summary) + '</strong><small>Event ' + esc(e.event_id) + ' · ' +
    esc(e.host || 'Unknown host') + ' · ' + esc(e.channel) + '</small></span><span class="row-chevron">›</span></button>').join('');
  html += '</div>';
  return html;
}
async function renderFindings() {
  const findings = await api(caseUrl('/findings'));
  let html = titleBlock('TRIAGE QUEUE', 'Investigation findings',
    'Built-in Event ID signals are leads, not evidence of malicious intent.');
  html += '<div class="notice"><strong>Evidence-driven triage</strong><span>TraceForge does not classify a host as compromised based only on one Event ID. Validate each record and its surrounding context.</span></div>';
  if (!findings.length) return html + empty('No triage findings', 'No built-in rules matched. Inspect events and run additional detections as needed.');
  html += '<section class="panel">' + findings.map((f) =>
    '<button class="finding-card" data-action="event" data-id="' + f.event_row_id +
    '"><div class="finding-card-head"><div><span class="mono tiny">RULE ' + esc(f.rule_id) +
    '</span><h3>' + esc(f.title) + '</h3></div>' + pill(f.severity, f.severity) + '</div>' +
    '<p>' + esc(f.explanation) + '</p><div class="finding-meta">' +
    '<span>Event ' + esc(f.event_id) + '</span><span>' + esc(f.host || 'Unknown host') +
    '</span><span>' + esc(formatTime(f.timestamp)) + '</span></div></button>').join('') + '</section>';
  return html;
}
async function renderEvidence() {
  const evidence = await api(caseUrl('/evidence'));
  let html = titleBlock('EVIDENCE MANAGEMENT', 'Evidence vault',
    'Original uploads are retained on disk, with integrity fingerprints recorded at ingestion.',
    '<button class="button button-primary" data-action="upload">⇧ Upload EVTX</button>');
  html += '<div class="notice"><strong>Integrity matters</strong><span>SHA-256 is calculated from the exact uploaded bytes. The file is stored using a generated identifier rather than its untrusted original name.</span></div>';
  return html + (evidence.length ?
    '<section class="panel"><div class="panel-heading"><div><h2>Uploaded artifacts</h2><p>' +
    num(evidence.length) + ' file(s)</p></div></div>' + evidence.map(evidenceRow).join('') + '</section>' :
    empty('Your vault is empty', 'Upload your first EVTX file to start an evidence-backed investigation.',
      '<button class="button button-primary" data-action="upload">Upload EVTX</button>'));
}
async function renderChainsaw() {
  const [conf, runs] = await Promise.all([api('/api/chainsaw/status'), api(caseUrl('/hunts'))]);
  let html = titleBlock('DETECTION ENGINE', 'Chainsaw integration',
    'Run external Chainsaw hunts on indexed case evidence, when a rule pack is configured.');
  html += '<div class="engine-status"><div class="engine-badge">⌘</div><div><h2>WithSecure Chainsaw</h2><p>Fast Windows event-log detection and Sigma hunting</p></div>' +
    pill(conf.available && conf.configured ? 'Ready' : 'Setup required',
      conf.available && conf.configured ? 'ready' : 'medium') + '</div>';
  html += '<div class="dashboard-grid"><section class="panel"><h2>Configuration</h2>' +
    '<div class="config-row"><span>Executable detected</span>' +
    pill(conf.available ? 'Yes' : 'No', conf.available ? 'ready' : 'neutral') + '</div>' +
    '<div class="config-row"><span>Chainsaw rules</span>' +
    pill(conf.chainsaw_rules ? 'Configured' : 'Not configured', conf.chainsaw_rules ? 'ready' : 'neutral') + '</div>' +
    '<div class="config-row"><span>Sigma rules + mapping</span>' +
    pill(conf.sigma_rules ? 'Configured' : 'Not configured', conf.sigma_rules ? 'ready' : 'neutral') + '</div>' +
    '<button class="button button-primary wide" data-action="run-hunt" ' +
    (!conf.available || !conf.configured ? 'disabled' : '') + '>Run Chainsaw hunt</button></section>' +
    '<section class="panel"><h2>Connect Chainsaw</h2><p class="paragraph">Install a compatible Chainsaw binary and configure rule directories using environment variables on the backend host.</p>' +
    '<pre class="code-box">CHAINSAW_BIN=/path/to/chainsaw\nCHAINSAW_RULES_DIR=/path/to/rules</pre>' +
    '<p class="paragraph">For Sigma, set <code>SIGMA_RULES_DIR</code> and <code>CHAINSAW_MAPPING_FILE</code> instead. See the README for setup details.</p></section></div>';
  html += '<section class="panel"><div class="panel-heading"><div><h2>Recent hunts</h2><p>Unmodified tool results for analyst validation</p></div></div>' +
    (runs.length ? runs.map((run) => '<details class="hunt-result"><summary>' +
      esc(formatTime(run.created_at)) + ' · ' + esc(run.status) +
      '</summary><pre class="code-box">' + esc(JSON.stringify(run.output, null, 2)) +
      '</pre></details>').join('') : '<p class="panel-placeholder">No Chainsaw runs yet.</p>') + '</section>';
  return html;
}

async function render() {
  const token = ++state.renderToken;
  document.getElementById('crumb').textContent = labels[state.view];
  document.querySelectorAll('[data-view]').forEach((element) => {
    if (element.classList.contains('nav-link')) {
      element.classList.toggle('active', element.dataset.view === state.view);
    }
  });
  if (!state.caseId) {
    content.innerHTML = titleBlock('WELCOME TO TRACEFORGE', 'Investigate with confidence',
      'A local-first workspace for Windows event logs and defensible forensic reporting.') +
      '<div class="welcome-panel"><div class="welcome-mark">TF</div><div class="eyebrow">GET STARTED</div>' +
      '<h2>Your next investigation starts here.</h2>' +
      '<p>Create a case, upload a Windows EVTX event log, and explore your evidence in one place. No cloud account required.</p>' +
      '<button class="button button-primary" data-action="new-case">+ Create your first case</button></div>';
    return;
  }
  content.innerHTML = skeleton();
  try {
    let html;
    if (state.view === 'events') html = await renderEvents();
    else if (state.view === 'timeline') html = await renderTimeline();
    else if (state.view === 'findings') html = await renderFindings();
    else if (state.view === 'evidence') html = await renderEvidence();
    else if (state.view === 'chainsaw') html = await renderChainsaw();
    else html = await renderOverview();
    if (token === state.renderToken) content.innerHTML = html;
  } catch (error) {
    if (token === state.renderToken) {
      content.innerHTML = empty('Could not load this view', error.message,
        '<button class="button button-outline" data-action="retry">Retry</button>');
      notify(error.message, true);
    }
  }
}

/* Evidence-first inspector: decoded fields up front, raw source one click away. */
let activeEvent = null;
let activeEventTab = 'overview';
const inspectValue = (v) => v == null || v === '' ? '—' :
  (typeof v === 'object' ? JSON.stringify(v) : String(v));
const eventField = (name, value, wide = false) =>
  '<div class="inspector-field' + (wide ? ' inspector-field-wide' : '') +
  '"><span>' + esc(name) + '</span><strong title="' + esc(inspectValue(value)) +
  '">' + esc(inspectValue(value)) + '</strong></div>';
const basename = (path) => String(path || '').replace(/\\/g, '/').split('/').pop();

function inspectorOverview(record) {
  const d = record.data || {};
  const isProcess = [4688, 1].includes(Number(record.event_id));
  const process = d.NewProcessName || d.Image || d.ProcessName;
  const parent = d.ParentProcessName || d.ParentImage;
  const command = d.CommandLine || d.ScriptBlockText;
  const principal = [d.SubjectDomainName, d.SubjectUserName].filter(Boolean).join('\\') ||
                    [d.TargetDomainName, d.TargetUserName].filter(Boolean).join('\\') ||
                    record.account;
  let s = '<div class="inspector-section"><div class="inspector-section-heading"><span class="section-marker"></span>' +
    (isProcess ? 'Process execution' : 'Event summary') + '</div><div class="inspector-field-grid">';
  if (process) s += eventField('Process image', process, true);
  if (command) s += eventField('Command line', command, true);
  if (parent) s += eventField('Parent process', parent, true);
  if (d.NewProcessId) s += eventField('New process ID', d.NewProcessId);
  if (d.ProcessId) s += eventField('Creator process ID', d.ProcessId);
  if (d.SubjectLogonId) s += eventField('Subject logon ID', d.SubjectLogonId);
  if (d.TokenElevationType) s += eventField('Token elevation', d.TokenElevationType);
  if (d.MandatoryLabel) s += eventField('Mandatory label', d.MandatoryLabel);
  if (principal) s += eventField('Security principal', principal, true);
  if (!process && !command && !parent) {
    const keys = Object.keys(d).slice(0, 6);
    if (keys.length) s += keys.map((key) => eventField(key, d[key])).join('');
    else s += '<div class="inspector-hint">No decoded event payload available.</div>';
  }
  s += '</div></div><div class="inspector-section"><div class="inspector-section-heading"><span class="section-marker"></span>Record provenance</div><div class="inspector-field-grid">' +
    eventField('Host', record.host) + eventField('Channel', record.channel) +
    eventField('Provider', record.provider, true) + eventField('Record ID', record.record_id) +
    eventField('Evidence ID', record.evidence_id, true) + '</div></div>';
  return s;
}
function inspectorFieldList(record) {
  const fields = Object.entries(record.data || {});
  if (!fields.length) return '<div class="inspector-hint">This event has no decoded EventData fields.</div>';
  return '<div class="inspector-section"><div class="inspector-section-heading"><span class="section-marker"></span>All decoded event fields <span class="section-count">' +
    fields.length + ' fields</span></div><div class="inspector-field-grid">' +
    fields.map(([key,value]) => eventField(key,value,String(value).length > 80)).join('') + '</div></div>';
}
function inspectorSource(record, type) {
  const payload = type === 'xml' ? record.raw_xml : JSON.stringify(record.data || {},null,2);
  return '<div class="source-toolbar"><div><strong>' +
    (type === 'xml' ? 'Original Windows event XML' : 'Decoded EventData JSON') +
    '</strong><small>Preserved for evidence review</small></div>' +
    '<button class="button button-outline button-sm" data-action="copy-event" data-format="' +
    type + '">Copy ' + type.toUpperCase() + '</button></div><pre class="inspector-source"><code>' +
    esc(payload || '') + '</code></pre>';
}
function renderInspector() {
  if (!activeEvent) return;
  const record=activeEvent,d=record.data||{},image=d.NewProcessName||d.Image||d.ProcessName,
        command=d.CommandLine||d.ScriptBlockText;
  document.getElementById('inspectorTitle').textContent=record.summary||'Event details';
  document.getElementById('inspectorSubtitle').textContent =
    (record.host||'Unknown host')+' · Event '+(record.event_id??'—')+' · Record '+(record.record_id||'—');
  const snapshot='<div class="inspector-snapshot"><div class="inspector-event-info"><div class="inspector-event-label">' +
    '<span class="inspector-event-id">EVENT '+esc(record.event_id??'—')+'</span><span>'+
    esc(formatTime(record.timestamp))+'</span></div><h3>'+
    esc(image?basename(image):record.summary)+'</h3><p>'+
    esc(image||record.summary||'')+'</p></div>'+
    (command?'<div class="inspector-command-preview"><div class="command-title"><span>COMMAND LINE</span>'+
    '<button type="button" data-action="copy-event" data-format="command">Copy</button></div><code>'+
    esc(command)+'</code></div>':'')+'</div>';
  const tabs=[['overview','Overview'],['fields','All fields'],['json','JSON'],['xml','Original XML']];
  const nav='<div class="inspector-tabs" role="tablist" aria-label="Event detail views">'+
    tabs.map(([key,label])=>'<button type="button" role="tab" aria-selected="'+
      (key===activeEventTab)+'" data-event-tab="'+key+'" class="'+
      (key===activeEventTab?'selected':'')+'">'+label+'</button>').join('')+'</div>';
  const panel=activeEventTab==='fields'?inspectorFieldList(record):
    ['json','xml'].includes(activeEventTab)?inspectorSource(record,activeEventTab):inspectorOverview(record);
  document.getElementById('eventDetails').innerHTML=snapshot+nav+
    '<div class="inspector-scroll" role="tabpanel" tabindex="0">'+panel+'</div>';
}
async function showEvent(rowId) {
  try {
    activeEvent=await api(caseUrl('/events/'+encodeURIComponent(rowId)));
    activeEventTab='overview';
    renderInspector();
    showDialog('eventDialog');
  } catch(error) { notify(error.message,true); }
}
document.addEventListener('click', async (event) => {
  const tab = event.target.closest('[data-event-tab]');
  if (tab && activeEvent) { activeEventTab = tab.dataset.eventTab; renderInspector(); return; }
  const target = event.target.closest('[data-action], [data-view]');
  if (!target) return;
  if (target.dataset.view) {
    state.view = target.dataset.view;
    state.page = 1;
    render();
    return;
  }
  const action = target.dataset.action;
  if (action === 'new-case') return showDialog('caseDialog');
  if (action === 'upload') return showDialog('uploadDialog');
  if (action === 'close-dialog') return closeDialogs();
  if (action === 'copy-event' && activeEvent) {
    const value=target.dataset.format==='xml'?activeEvent.raw_xml:
      target.dataset.format==='json'?JSON.stringify(activeEvent.data||{},null,2):
      String(activeEvent.data?.CommandLine||activeEvent.data?.ScriptBlockText||'');
    try { await navigator.clipboard.writeText(value); notify('Copied to clipboard.'); }
    catch (_) { notify('Clipboard unavailable. Select and copy the source text instead.',true); }
    return;
  }
  if (action === 'retry') return render();
  if (action === 'event') return showEvent(target.dataset.id);
  if (action === 'previous' && state.page > 1) { state.page--; return render(); }
  if (action === 'next') { state.page++; return render(); }
  if (action === 'filter') {
    state.query = document.getElementById('eventSearch').value.trim();
    state.eventId = document.getElementById('eventIdFilter').value;
    state.order = document.getElementById('eventOrder').value;
    state.page = 1;
    return render();
  }
  if (action === 'run-hunt') {
    target.disabled = true;
    target.textContent = 'Running analysis…';
    try {
      await api(caseUrl('/hunt'), { method: 'POST' });
      notify('Chainsaw hunt completed. Review the raw engine output.');
      render();
    } catch (error) { notify(error.message, true); target.disabled = false; target.textContent = 'Run Chainsaw hunt'; }
  }
});
document.addEventListener('keydown', (event) => {
  if (event.target.classList?.contains('event-row') && (event.key === 'Enter' || event.key === ' ')) {
    event.preventDefault(); showEvent(event.target.dataset.id);
  }
  if (event.key === 'Enter' && (event.target.id === 'eventSearch' || event.target.id === 'eventIdFilter')) {
    event.preventDefault(); document.querySelector('[data-action="filter"]')?.click();
  }
});
document.getElementById('casePicker').addEventListener('change', (event) => {
  state.caseId = event.target.value || null;
  state.page = 1;
  render();
});
document.getElementById('evtxFile').addEventListener('change', (event) => {
  document.getElementById('selectedFile').textContent = event.target.files[0]?.name || 'No file selected';
});
document.getElementById('caseForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.target;
  const button = form.querySelector('[type="submit"]');
  button.disabled = true;
  try {
    const result = await api('/api/cases', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: document.getElementById('caseName').value,
        description: document.getElementById('caseDescription').value
      })
    });
    closeDialogs(); form.reset();
    await loadCases(); state.caseId = result.id;
    document.getElementById('casePicker').value = result.id;
    state.view = 'overview'; await render();
    notify('Case created successfully.');
  } catch (error) { notify(error.message, true); }
  finally { button.disabled = false; }
});
document.getElementById('uploadForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  const file = document.getElementById('evtxFile').files[0];
  if (!file || !state.caseId) return;
  const button = document.getElementById('uploadSubmit');
  button.disabled = true; button.textContent = 'Preserving & indexing…';
  const data = new FormData(); data.append('file', file);
  try {
    const result = await api(caseUrl('/evidence'), { method: 'POST', body: data });
    closeDialogs(); event.target.reset();
    document.getElementById('selectedFile').textContent = 'No file selected';
    await loadCases(); state.view = 'overview'; await render();
    notify('Evidence indexed: ' + num(result.event_count) + ' events. SHA-256 recorded.');
  } catch (error) {
    notify(error.message + ' Check the evidence vault for preservation status.', true);
    closeDialogs(); state.view = 'evidence'; render();
  } finally { button.disabled = false; button.textContent = 'Upload & analyze'; }
});

loadCases().then(render).catch((error) => {
  content.innerHTML = empty('Unable to connect', error.message);
});
