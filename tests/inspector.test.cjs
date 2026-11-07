const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const js = fs.readFileSync('frontend/app.js', 'utf8');
const html = fs.readFileSync('frontend/index.html', 'utf8');
const css = fs.readFileSync('frontend/inspector.css', 'utf8');
const begin = js.indexOf('/* Full-screen forensic event workspace.');
const end = js.indexOf("document.addEventListener('click', async (event) => {", begin);
assert.ok(begin >= 0 && end > begin, 'inspector functions must be present');

function loadInspector() {
  const nodes = new Map([
    ['inspectorTitle', { textContent: '' }],
    ['inspectorSubtitle', { textContent: '' }],
    ['eventDetails', { innerHTML: '' }]
  ]);
  const context = {
    document: { getElementById: (id) => nodes.get(id) },
    esc(value) { return String(value == null ? '' : value).replace(/[&<>"']/g,
      c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); },
    formatTime(value) { return value || 'Unknown time'; }
  };
  vm.createContext(context);
  vm.runInContext(js.slice(begin, end) + '\n' +
    'globalThis.inspector = { inspectorOverview, inspectorFieldList, inspectorSource, renderInspector, setEvent(r) {activeEvent=r;activeEventTab="overview";} };',
    context);
  return { inspector: context.inspector, nodes };
}

const sample = {
  event_id: 4688,
  record_id: '225747',
  timestamp: '2020-10-11T17:05:00Z',
  host: 'EC2AMAZ-PLQJR3U',
  channel: 'Security',
  provider: 'Microsoft-Windows-Security-Auditing',
  evidence_id: 'evidence-123',
  account: 'alice',
  summary: 'Process created',
  raw_xml: '<Event><Data>A &amp; B</Data></Event>',
  data: {
    NewProcessName: 'C:\\Windows\\System32\\msdtc.exe',
    ParentProcessName: 'C:\\Windows\\System32\\services.exe',
    NewProcessId: '0x718',
    ProcessId: '0x250',
    SubjectUserName: 'alice',
    SubjectDomainName: 'WORKGROUP',
    CommandLine: 'msdtc.exe --arg <script>alert(1)</script>'
  }
};

test('full screen event inspector is installed with accessible back navigation', () => {
  assert.match(html, /class="event-inspector"/);
  assert.match(html, /Back to events/);
  assert.match(css, /width:100vw/);
  assert.match(css, /height:100dvh/);
  assert.match(css, /var\(--tf-surface\)/);
});

test('process lineage and flat metadata rows render without small cards', () => {
  const { inspector } = loadInspector();
  const view = inspector.inspectorOverview(sample);
  assert.match(view, /services\.exe/);
  assert.match(view, /msdtc\.exe/);
  assert.match(view, /WORKGROUP\\alice/);
  assert.match(view, /evidence-123/);
  assert.match(view, /inspector-detail-row/);
  assert.doesNotMatch(view, /inspector-field-grid|inspector-field-wide/);
});

test('command and source HTML escape hostile event contents', () => {
  const { inspector, nodes } = loadInspector();
  inspector.setEvent(sample);
  inspector.renderInspector();
  const view = nodes.get('eventDetails').innerHTML;
  assert.match(view, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
  assert.doesNotMatch(view, /<script>/);
  const source = inspector.inspectorSource(sample, 'xml');
  assert.match(source, /&lt;Event&gt;/);
  assert.match(source, /&amp;amp;/);
});

test('other event types retain decoded fields and source provenance', () => {
  const { inspector } = loadInspector();
  const view = inspector.inspectorOverview({
    ...sample, event_id: 1102,
    data: { SubjectUserName: 'Administrator', Detail: 'Security log cleared' }
  });
  assert.match(view, /Security log cleared/);
  assert.match(view, /Source &amp; provenance|Source & provenance/);
  assert.doesNotMatch(view, /Process lineage/);
});
