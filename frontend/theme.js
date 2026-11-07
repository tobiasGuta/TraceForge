/* TraceForge themes are browser-local preferences; no network requests. */
(() => {
  'use strict';
  const KEY = 'traceforge.appearance.v1';
  const HEX = /^#[0-9a-fA-F]{6}$/;
  const fields = [
    ['canvas', 'Page background', 'Main workspace canvas'],
    ['sidebar', 'Sidebar', 'Navigation background'],
    ['surface', 'Cards & panels', 'Cards, tables and dialogs'],
    ['raised', 'Raised surfaces', 'Inputs and secondary surfaces'],
    ['border', 'Borders', 'Dividers and outlines'],
    ['text', 'Primary text', 'Headings and event data'],
    ['muted', 'Secondary text', 'Labels and descriptions'],
    ['accent', 'Accent', 'Buttons, selected items and highlights'],
    ['success', 'Success', 'Ready and completion statuses'],
    ['warning', 'Warning', 'Medium-priority signals'],
    ['danger', 'Danger', 'High-priority signals']
  ];
  const defaults = {
    dark: { canvas:'#0B1220', sidebar:'#10192A', surface:'#172236', raised:'#223148',
      border:'#314158', text:'#ECF2FC', muted:'#9EB0C7', accent:'#94B1FF',
      success:'#69DDB5', warning:'#F3C677', danger:'#FF8491' },
    light: { canvas:'#F4F7FB', sidebar:'#FFFFFF', surface:'#FFFFFF', raised:'#EDF2F9',
      border:'#D4DFEB', text:'#17263D', muted:'#5B6B82', accent:'#3A64CC',
      success:'#167A58', warning:'#A36B1B', danger:'#BD4257' }
  };
  const presets = [
    {id:'slate',label:'Atlas blue',colors:{dark:{canvas:'#0B1220',sidebar:'#10192A',surface:'#172236',raised:'#223148',border:'#314158',accent:'#94B1FF'},light:{canvas:'#F4F7FB',sidebar:'#FFFFFF',surface:'#FFFFFF',raised:'#EDF2F9',border:'#D4DFEB',accent:'#3A64CC'}}},
    {id:'forest',label:'Forest',colors:{dark:{canvas:'#0A1517',sidebar:'#102123',surface:'#142A2A',raised:'#1E3736',border:'#31514E',accent:'#77DDC1'},light:{canvas:'#F2F9F5',sidebar:'#FCFFFD',surface:'#FFFFFF',raised:'#E8F3ED',border:'#C8DED2',accent:'#117F68'}}},
    {id:'orchid',label:'Orchid',colors:{dark:{canvas:'#14101D',sidebar:'#1C1728',surface:'#251E34',raised:'#342943',border:'#48395B',accent:'#C4A3FF'},light:{canvas:'#FAF6FD',sidebar:'#FFFFFF',surface:'#FFFFFF',raised:'#F2EAF8',border:'#E2D4EE',accent:'#7D4CB6'}}},
    {id:'ember',label:'Ember',colors:{dark:{canvas:'#18130F',sidebar:'#241D18',surface:'#30241D',raised:'#3F3027',border:'#594536',accent:'#FFB47C'},light:{canvas:'#FCF7F0',sidebar:'#FFFDF9',surface:'#FFFFFF',raised:'#F7EDE2',border:'#EAD8C5',accent:'#9F5B22'}}}
  ];
  const clone = (x) => JSON.parse(JSON.stringify(x));
  function load() {
    const base = { mode:'dark', schemes:clone(defaults) };
    try {
      const saved = JSON.parse(localStorage.getItem(KEY) || 'null');
      if (saved && typeof saved === 'object') {
        if (['dark','light','system'].includes(saved.mode)) base.mode = saved.mode;
        for (const scheme of ['dark','light']) {
          for (const [name] of fields) {
            const color = saved.schemes?.[scheme]?.[name];
            if (typeof color === 'string' && HEX.test(color)) base.schemes[scheme][name] = color;
          }
        }
      }
    } catch (_) { /* Browser may disallow localStorage. */ }
    return base;
  }
  let preferences = load();
  const effectiveMode = () => preferences.mode === 'system' ?
    (window.matchMedia && matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark') :
    preferences.mode;
  const validColor = (s) => typeof s === 'string' && HEX.test(s);
  const rgb = (hex) => [1,3,5].map((i) => parseInt(hex.slice(i,i+2),16));
  const relativeLum = (hex) => {
    const values = rgb(hex).map((n) => {
      const c = n / 255;
      return c <= .04045 ? c / 12.92 : Math.pow((c + .055) / 1.055, 2.4);
    });
    return values[0]*.2126 + values[1]*.7152 + values[2]*.0722;
  };
  const contrast = (x,y) => {
    const a=relativeLum(x), b=relativeLum(y);
    return (Math.max(a,b)+.05)/(Math.min(a,b)+.05);
  };
  function persist() { try { localStorage.setItem(KEY, JSON.stringify(preferences)); } catch (_) {} }
  function apply(redrawControls = true) {
    const mode = effectiveMode(), config = preferences.schemes[mode], root = document.documentElement;
    root.dataset.theme = mode;
    root.style.colorScheme = mode;
    fields.forEach(([key]) => root.style.setProperty('--tf-' + key, config[key]));
    root.style.setProperty('--tf-on-accent', relativeLum(config.accent) > .43 ? '#132034' : '#FFFFFF');
    const meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.setAttribute('content', config.canvas);
    const label = document.getElementById('modeLabel');
    if (label) label.textContent = mode === 'dark' ? 'Light' : 'Dark';
    const toggle = document.getElementById('themeModeToggle');
    if (toggle) {
      toggle.setAttribute('aria-label', 'Switch to ' + (mode === 'dark' ? 'light' : 'dark') + ' mode');
      toggle.firstChild.textContent = mode === 'dark' ? '☀ ' : '☾ ';
    }
    if (redrawControls) refreshEditor();
  }
  function setMode(mode) {
    if (!['dark','light','system'].includes(mode)) return;
    preferences.mode = mode; persist(); apply();
  }
  function selectPreset(id) {
    const preset = presets.find((p) => p.id === id);
    if (!preset) return;
    for (const scheme of ['dark','light']) {
      preferences.schemes[scheme] = Object.assign({}, defaults[scheme], preset.colors[scheme]);
    }
    persist(); apply();
  }
  function reset() {
    preferences.schemes[effectiveMode()] = clone(defaults[effectiveMode()]);
    persist(); apply();
  }
  function pickerMarkup(name,label,desc,color) {
    return '<div class="color-setting"><div class="color-setting-label"><strong>' +
      label + '</strong><small>' + desc + '</small></div>' +
      '<input type="color" data-color-picker="' + name + '" value="' + color +
      '" aria-label="' + label + ' color picker">' +
      '<input type="text" data-color-hex="' + name + '" maxlength="7" spellcheck="false" value="' + color +
      '" aria-label="' + label + ' hex value"></div>';
  }
  function refreshEditor() {
    const mode = effectiveMode(), dialog = document.getElementById('appearanceDialog');
    if (!dialog) return;
    dialog.querySelectorAll('[data-theme-mode]').forEach((button) => {
      const selected = preferences.mode === button.dataset.themeMode;
      button.classList.toggle('selected', selected);
      button.setAttribute('aria-pressed', String(selected));
    });
    const colors = document.getElementById('themeColors');
    colors.innerHTML = fields.map(([name,label,desc]) =>
      pickerMarkup(name,label,desc,preferences.schemes[mode][name])).join('');
    const swatches = document.getElementById('themePresets');
    swatches.innerHTML = presets.map((preset) => {
      const c = preset.colors[mode];
      return '<button type="button" class="theme-preset" data-theme-preset="' + preset.id +
        '" style="--preset-canvas:' + c.canvas + ';--preset-panel:' + c.surface + ';--preset-accent:' + c.accent +
        '" aria-label="Apply ' + preset.label + ' palette"><span class="preset-preview"><span></span><i></i></span>' +
        '<strong>' + preset.label + '</strong></button>';
    }).join('');
    updateContrast();
  }
  function updateContrast() {
    const config = preferences.schemes[effectiveMode()];
    const ratio = contrast(config.text, config.surface);
    const display = document.getElementById('contrastStatus');
    if (!display) return;
    display.classList.toggle('contrast-warning', ratio < 4.5);
    display.textContent = 'Text contrast on panels: ' + ratio.toFixed(1) +
      ':1 · ' + (ratio < 4.5 ? 'Low contrast — adjust primary text or panel color.' : 'Meets WCAG AA for normal text.');
  }
  function setup() {
    apply();
    const dialog = document.getElementById('appearanceDialog');
    document.getElementById('appearanceButton')?.addEventListener('click', () => {
      refreshEditor(); dialog.showModal();
    });
    document.getElementById('appearanceClose')?.addEventListener('click', () => dialog.close());
    document.getElementById('appearanceDone')?.addEventListener('click', () => dialog.close());
    document.getElementById('themeModeToggle')?.addEventListener('click', () => {
      setMode(effectiveMode() === 'dark' ? 'light' : 'dark');
    });
    document.getElementById('resetTheme')?.addEventListener('click', reset);
    dialog.addEventListener('click', (event) => {
      const mode = event.target.closest('[data-theme-mode]');
      if (mode) return setMode(mode.dataset.themeMode);
      const preset = event.target.closest('[data-theme-preset]');
      if (preset) return selectPreset(preset.dataset.themePreset);
    });
    dialog.addEventListener('input', (event) => {
      const field = event.target.dataset.colorPicker;
      if (!field || !fields.some(([n]) => n === field)) return;
      preferences.schemes[effectiveMode()][field] = event.target.value.toUpperCase();
      persist(); apply(false);
      const textInput = dialog.querySelector('[data-color-hex="' + field + '"]');
      if (textInput) textInput.value = event.target.value.toUpperCase();
      updateContrast();
    });
    dialog.addEventListener('change', (event) => {
      const field = event.target.dataset.colorHex;
      if (!field || !fields.some(([n]) => n === field)) return;
      const value = event.target.value.trim();
      if (!validColor(value)) { refreshEditor(); return; }
      preferences.schemes[effectiveMode()][field] = value.toUpperCase();
      persist(); apply();
    });
    if (window.matchMedia) {
      const mql=matchMedia('(prefers-color-scheme: light)');
      mql.addEventListener?.('change', () => { if (preferences.mode === 'system') apply(); });
    }
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded',setup);
  else setup();
  window.TraceForgeTheme = { setMode, selectPreset, reset, effectiveMode };
})();
