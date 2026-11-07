/* Source-driven process explorer and correlation views. No sample host/process assumptions. */
'use strict';

const processState = { query:'', host:'', page:1, order:'desc' };
function processPathName(image) {
  return image ? String(image).replace(/\\/g, '/').split('/').pop() : 'Unnamed process';
}
function processRow(p) {
  const image = p.image || '';
  const command = p.command_line || 'Command line not captured in this record';
  return '<tr class="event-row process-event-row" data-action="event" data-id="' + p.id +
    '" tabindex="0" role="button" aria-label="Inspect process record ' + esc(p.id) + '">' +
    '<td class="mono">' + esc(formatTime(p.timestamp)) + '</td>' +
    '<td><strong>' + esc(processPathName(image)) + '</strong><small title="' + esc(image) + '">' +
    esc(image || 'Process path not available') + '</small></td>' +
    '<td><span class="process-command" title="' + esc(command) + '">' + esc(command) + '</span></td>' +
    '<td class="mono">' + esc(p.pid || '—') + '</td>' +
    '<td class="mono">' + esc(p.host || '—') + '</td>' +
    '<td>' + pill(p.source === 'sysmon' ? 'Sysmon' : 'Security', 'neutral') + '</td>' +
    '<td class="row-chevron">›</td></tr>';
}
async function renderProcesses() {
  const params = new URLSearchParams({
    q:processState.query, host:processState.host,
    page:String(processState.page), limit:'50', order:processState.order
  });
  const data = await api(caseUrl('/processes?' + params));
  const hosts = '<option value="">All hosts</option>' +
    data.hosts.map((host) => '<option value="' + esc(host) + '"' +
      (host === processState.host ? ' selected' : '') + '>' + esc(host) + '</option>').join('');
  let html = titleBlock('EXECUTION INVESTIGATION', 'Process explorer',
    'Explore documented process creations across Windows Security and Sysmon logs. This is not a list of confirmed attacks.');
  html += '<div class="notice"><strong>Evidence-based process history</strong>' +
    '<span>Only supported process-creation records appear here. Missing process fields stay missing; ' +
    'process relationships are derived from recorded identifiers, not guessed from names.</span></div>';
  html += '<div class="panel"><div class="filter-bar">' +
    '<label class="filter-label">Executable, command, PID, account or host<input id="processQuery" value="' +
    esc(processState.query) + '" placeholder="Search processes across this case"></label>' +
    '<label class="filter-label filter-small">Host<select id="processHost">' + hosts + '</select></label>' +
    '<label class="filter-label filter-small">Order<select id="processOrder"><option value="desc"' +
    (processState.order === 'desc' ? ' selected' : '') + '>Newest first</option><option value="asc"' +
    (processState.order === 'asc' ? ' selected' : '') + '>Oldest first</option></select></label>' +
    '<button class="button button-primary" type="button" data-process-action="filter">Search</button>' +
    '</div><div class="results-line"><b>' + num(data.total) +
    '</b> process-creation records · click any row for details and related activity</div>';
  html += data.items.length ?
    '<div class="table-scroll"><table class="events-table process-table"><thead><tr>' +
    '<th>Timestamp</th><th>Executable</th><th>Command line</th><th>PID</th><th>Host</th><th>Source</th><th></th>' +
    '</tr></thead><tbody>' + data.items.map(processRow).join('') + '</tbody></table></div>' :
    empty('No process records match', 'Try a different query, or upload Security/Sysmon event logs with process creation enabled.');
  html += '<div class="pagination"><span>Page ' + processState.page +
    ' of ' + Math.max(1,Math.ceil(data.total / 50)) + '</span><div>' +
    '<button class="button button-outline button-sm" data-process-action="previous"' +
    (processState.page === 1 ? ' disabled' : '') + '>Previous</button> ' +
    '<button class="button button-outline button-sm" data-process-action="next"' +
    (processState.page * 50 >= data.total ? ' disabled' : '') + '>Next</button>' +
    '</div></div></div>';
  return html;
}
function linkConfidence(p) {
  return p.confidence === 'source-guid' ?
    pill('Sysmon GUID match', 'ready') : pill('PID candidate', 'medium');
}
function correlationRow(p) {
  return '<button class="correlation-row" type="button" data-action="event" data-id="' + p.id + '">' +
    '<span class="correlation-main"><strong>' + esc(processPathName(p.image)) + '</strong>' +
    '<small>' + esc(p.image || 'Process path not recorded') + '</small>' +
    '<small>' + esc(formatTime(p.timestamp)) + ' · PID ' + esc(p.pid || '—') + '</small>' +
    '<span class="correlation-reason">' + esc(p.reason) + '</span></span>' +
    '<span class="correlation-side">' + linkConfidence(p) + '<span class="row-chevron">›</span></span>' +
    '</button>';
}
function contextEventRow(event) {
  return '<button class="context-event" type="button" data-action="event" data-id="' + event.id + '">' +
    '<span class="context-time">' + esc(formatTime(event.timestamp)) + '</span>' +
    '<span class="context-event-info"><strong>' + esc(event.summary) + '</strong>' +
    '<small>' + esc(event.provider || event.channel || 'Windows event') + '</small></span>' +
    '<span class="context-event-id">#' + esc(event.event_id ?? '—') + '</span>' +
    '<span class="row-chevron">›</span></button>';
}
function contextBlock(label, rows, emptyText, total) {
  return '<section class="context-section"><div class="context-section-title">' +
    '<h3>' + label + '</h3><span>' + num(total ?? rows.length) + '</span></div>' +
    (rows.length ? rows.map(correlationRow).join('') :
      '<p class="context-empty">' + emptyText + '</p>') + '</section>';
}
function renderContextResults(data) {
  return '<div class="context-workspace">' +
    '<div class="context-note">' + esc(data.note || '') + '</div>' +
    '<div class="context-columns"><section class="context-relations">' +
    contextBlock('Possible parent process', data.parents || [],
      'No matching source process records were found.', data.parent_total) +
    contextBlock('Possible child processes', data.children || [],
      'No matching source process records were found.', data.child_total) +
    '</section><section class="context-nearby">' +
    '<div class="context-section-title"><h3>Other events around this record</h3><span>' +
    num((data.nearby || []).length) + '</span></div>' +
    '<p class="context-hint">Same host within ±' + num(data.window_minutes || 10) +
    ' minutes. Time proximity does not establish causation.</p>' +
    ((data.nearby || []).length ?
      data.nearby.map(contextEventRow).join('') :
      '<p class="context-empty">No other events appear in this time window.</p>') +
    '</section></div></div>';
}
async function loadEventContext(rowId) {
  try {
    const data=await api(caseUrl('/events/' + encodeURIComponent(rowId) + '/context?window_minutes=10&limit=70'));
    if (activeEvent?.id !== rowId || activeEventTab !== 'related') return;
    const mount=document.getElementById('eventContextMount');
    if (mount) mount.innerHTML=renderContextResults(data);
  } catch (error) {
    const mount=document.getElementById('eventContextMount');
    if (mount && activeEvent?.id === rowId && activeEventTab === 'related')
      mount.innerHTML='<div class="context-error">Unable to load context: ' + esc(error.message) + '</div>';
  }
}

document.addEventListener('click', (event) => {
  const button=event.target.closest('[data-process-action], [data-process-pivot]');
  if (!button) return;
  const pivot=button.dataset.processPivot;
  if (pivot != null) {
    closeDialogs();
    processState.query=pivot;
    processState.host=activeEvent?.host || '';
    processState.page=1;
    state.view='processes';
    render();
    return;
  }
  const action=button.dataset.processAction;
  if (action === 'filter') {
    processState.query=document.getElementById('processQuery')?.value.trim() || '';
    processState.host=document.getElementById('processHost')?.value || '';
    processState.order=document.getElementById('processOrder')?.value || 'desc';
    processState.page=1; render();
  } else if (action === 'previous' && processState.page > 1) {
    processState.page--; render();
  } else if (action === 'next') {
    processState.page++; render();
  }
});
document.addEventListener('keydown', (event) => {
  if (event.target.id === 'processQuery' && event.key === 'Enter') {
    event.preventDefault();
    document.querySelector('[data-process-action="filter"]')?.click();
  }
});
