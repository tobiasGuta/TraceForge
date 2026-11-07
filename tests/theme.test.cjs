const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const script = fs.readFileSync('frontend/theme.js','utf8');

function environment(saved) {
  const values = new Map();
  const storage = new Map();
  if (saved) storage.set('traceforge.appearance.v1', JSON.stringify(saved));
  const root = {
    dataset: {},
    style: {
      setProperty(name, value) { values.set(name, value); },
      colorScheme: ''
    }
  };
  const doc = {
    readyState: 'loading',
    documentElement: root,
    querySelector() { return null; },
    getElementById() { return null; },
    addEventListener() {}
  };
  const window = { matchMedia() { return {matches:false}; } };
  vm.runInNewContext(script, {
    document:doc, window,
    matchMedia:window.matchMedia,
    localStorage: {
      getItem(key) { return storage.get(key) ?? null; },
      setItem(key,value) { storage.set(key,value); }
    }
  });
  return { api:window.TraceForgeTheme, values, storage, root };
}

test('light/dark switches update semantic tokens and persist mode', () => {
  const { api, values, storage, root } = environment();
  assert.equal(api.effectiveMode(),'dark');
  api.setMode('light');
  assert.equal(root.dataset.theme,'light');
  assert.equal(values.get('--tf-canvas'),'#F4F7FB');
  assert.equal(JSON.parse(storage.get('traceforge.appearance.v1')).mode,'light');
  api.setMode('dark');
  assert.equal(root.dataset.theme,'dark');
});

test('preset updates both palettes while reset only affects active mode', () => {
  const { api, values, storage } = environment();
  api.selectPreset('orchid');
  assert.equal(values.get('--tf-accent'),'#C4A3FF');
  api.setMode('light');
  assert.equal(values.get('--tf-accent'),'#7D4CB6');
  api.reset();
  assert.equal(values.get('--tf-accent'),'#3A64CC');
  const saved = JSON.parse(storage.get('traceforge.appearance.v1'));
  assert.equal(saved.schemes.dark.accent,'#C4A3FF');
});

test('invalid stored colors do not become CSS values', () => {
  const { api, values } = environment({
    mode:'dark',schemes:{dark:{accent:'red; background:url(evil)',canvas:'#112233'}}
  });
  api.setMode('dark');
  assert.equal(values.get('--tf-canvas'),'#112233');
  assert.equal(values.get('--tf-accent'),'#94B1FF');
});
