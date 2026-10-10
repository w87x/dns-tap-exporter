'use strict';
// All data comes from the network (domain names, client IPs): only ever write it with textContent.
const NS = 'http://www.w3.org/2000/svg';
const COLORS = ['--c0','--c1','--c2','--c3','--c4','--c5','--c6','--c7'];
const params = new URLSearchParams(location.search);
const REFRESH_MS = (Number(params.get('refresh')) || 60) * 1000;

const state = { points: [], now: null, selected: null, range: params.get('range') || '6h' };
const $ = id => document.getElementById(id);

function el(tag, attrs, text) {
  const e = document.createElement(tag);
  for (const k in attrs || {}) e.setAttribute(k, attrs[k]);
  if (text !== undefined) e.textContent = text;
  return e;
}
function svg(tag, attrs, text) {
  const e = document.createElementNS(NS, tag);
  for (const k in attrs || {}) e.setAttribute(k, attrs[k]);
  if (text !== undefined) e.textContent = text;
  return e;
}
const fmt = n => n >= 1000 ? (n / 1000).toFixed(n >= 10000 ? 0 : 1) + 'k' : n >= 10 ? n.toFixed(0) : n.toFixed(n >= 1 ? 1 : 2);
const pct = n => (n * 100).toFixed(n < 0.1 ? 1 : 0) + '%';
const hhmm = (t, secs) => new Date(t).toLocaleTimeString([], secs ? { hour: '2-digit', minute: '2-digit', second: '2-digit' } : { hour: '2-digit', minute: '2-digit' });

async function refresh() {
  try {
    const [h, n] = await Promise.all([
      fetch('../api/history?range=' + state.range, { cache: 'no-store' }).then(r => r.json()),
      fetch('../api/now', { cache: 'no-store' }).then(r => r.json()),
    ]);
    state.points = h.points; state.now = n;
    $('status').textContent = 'updated ' + new Date().toLocaleTimeString() + ' · every ' + REFRESH_MS / 1000 + 's';
  } catch (e) {
    $('status').textContent = 'error: ' + e.message;
  }
  render();
}

function seriesOf(points, keyFn, limit) {
  // union of names across samples, ranked by peak value
  const peak = new Map();
  points.forEach(p => keyFn(p).forEach(([k, v]) => peak.set(k, Math.max(peak.get(k) || 0, v))));
  const names = [...peak.entries()].sort((a, b) => b[1] - a[1]).slice(0, limit).map(e => e[0]);
  return names.map((name, i) => ({
    name, color: `var(${COLORS[i % COLORS.length]})`,
    values: points.map(p => (keyFn(p).find(([k]) => k === name) || [0, 0])[1]),
  }));
}

function chart(id, points, series, yfmt) {
  const box = $(id); box.replaceChildren();
  if (points.length < 2) { box.appendChild(el('p', { class: 'muted' }, 'Collecting… the first points appear after two sample intervals.')); return; }
  const W = 640, H = 220, L = 46, R = 10, T = 8, B = 22;
  const s = svg('svg', { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: 'none' });
  const ts = points.map(p => Date.parse(p.t));
  const t0 = ts[0], t1 = ts[ts.length - 1];
  const secs = t1 - t0 < 20 * 60e3; // show seconds on short spans
  const ymax = Math.max(1e-9, ...series.flatMap(x => x.values)) * 1.1;
  const X = t => L + (t - t0) / Math.max(1, t1 - t0) * (W - L - R);
  const Y = v => T + (1 - v / ymax) * (H - T - B);

  for (let i = 0; i <= 4; i++) {
    const v = ymax * i / 4, y = Y(v);
    s.appendChild(svg('line', { x1: L, x2: W - R, y1: y, y2: y, stroke: 'var(--grid)', 'stroke-width': 1 }));
    s.appendChild(svg('text', { x: L - 4, y: y + 4, 'text-anchor': 'end', fill: 'var(--muted)', 'font-size': 10 }, yfmt(v)));
  }
  for (let i = 0; i <= 4; i++) {
    const t = t0 + (t1 - t0) * i / 4;
    s.appendChild(svg('text', { x: X(t), y: H - 6, 'text-anchor': i === 0 ? 'start' : i === 4 ? 'end' : 'middle', fill: 'var(--muted)', 'font-size': 10 }, hhmm(t, secs)));
  }
  series.forEach(x => {
    const d = x.values.map((v, i) => (i ? 'L' : 'M') + X(ts[i]).toFixed(1) + ' ' + Y(v).toFixed(1)).join('');
    s.appendChild(svg('path', { d, fill: 'none', stroke: x.color, 'stroke-width': 1.6, 'vector-effect': 'non-scaling-stroke' }));
  });
  if (state.selected != null && state.selected < ts.length) {
    const x = X(ts[state.selected]);
    s.appendChild(svg('line', { x1: x, x2: x, y1: T, y2: H - B, stroke: 'var(--sel)', 'stroke-width': 1.5, 'stroke-dasharray': '4 3' }));
  }
  const tip = svg('text', { fill: 'var(--fg)', 'font-size': 11, y: T + 10 });
  const hover = svg('line', { y1: T, y2: H - B, stroke: 'var(--muted)', 'stroke-width': 1, visibility: 'hidden' });
  s.appendChild(hover); s.appendChild(tip);
  const idxAt = ev => {
    const r = s.getBoundingClientRect();
    const t = t0 + ((ev.clientX - r.left) / r.width * W - L) / (W - L - R) * (t1 - t0);
    let best = 0; ts.forEach((x, i) => { if (Math.abs(x - t) < Math.abs(ts[best] - t)) best = i; });
    return best;
  };
  s.addEventListener('mousemove', ev => {
    const i = idxAt(ev), x = X(ts[i]);
    hover.setAttribute('x1', x); hover.setAttribute('x2', x); hover.setAttribute('visibility', 'visible');
    tip.setAttribute('x', x > W / 2 ? x - 6 : x + 6); tip.setAttribute('text-anchor', x > W / 2 ? 'end' : 'start');
    tip.textContent = hhmm(ts[i], secs) + '  ' + series.map(q => q.name + ' ' + yfmt(q.values[i])).slice(0, 3).join(' · ');
  });
  s.addEventListener('mouseleave', () => { hover.setAttribute('visibility', 'hidden'); tip.textContent = ''; });
  s.addEventListener('click', ev => { state.selected = idxAt(ev); render(); });
  box.appendChild(s);

  const lg = el('div', { class: 'legend' });
  series.forEach(x => {
    const i = el('i'); i.style.background = x.color;
    const item = el('span'); item.appendChild(i); item.appendChild(document.createTextNode(x.name)); lg.appendChild(item);
  });
  box.appendChild(lg);
}

function table(id, rows, cols) {
  const t = $(id); t.replaceChildren();
  const head = el('tr'); cols.forEach(c => head.appendChild(el('th', c.n ? { class: 'n' } : {}, c.h))); t.appendChild(head);
  if (!rows.length) { const r = el('tr'); const td = el('td', { colspan: cols.length, class: 'muted' }, 'nothing above the minimum count'); r.appendChild(td); t.appendChild(r); return; }
  rows.forEach(row => {
    const tr = el('tr'); cols.forEach(c => tr.appendChild(el('td', c.n ? { class: 'n' } : {}, c.f(row)))); t.appendChild(tr);
  });
}

function cards() {
  const n = state.now, c = $('cards'); c.replaceChildren();
  if (!n) return;
  const add = (l, v, bad) => { const d = el('div', { class: 'card' + (bad ? ' bad' : '') }); d.appendChild(el('div', { class: 'v' }, v)); d.appendChild(el('div', { class: 'l' }, l)); c.appendChild(d); };
  add('queries / s', fmt(n.qps));
  add('responses / s', fmt(n.rps));
  add('failure ratio', pct(n.fail_ratio), n.fail_ratio > 0.2);
  add('capture drops / s', fmt(n.drops), n.drops > 0);
  add('malformed / s', fmt(n.malformed));
  add('window', Math.round(n.window_sec) + ' s');
}

function render() {
  const P = state.points;
  cards();
  chart('c-rate', P, [
    { name: 'queries', color: 'var(--c0)', values: P.map(p => p.qps) },
    { name: 'responses', color: 'var(--c2)', values: P.map(p => p.rps) }], fmt);
  chart('c-fail', P, [{ name: 'failure ratio', color: 'var(--c1)', values: P.map(p => p.fail_ratio) }], pct);
  chart('c-clients', P, seriesOf(P, p => (p.top_clients || []).map(e => [e.client, e.qps]), 6), fmt);
  chart('c-domains', P, seriesOf(P, p => (p.top_domains || []).map(e => [e.domain, e.qps]), 6), fmt);
  chart('c-rcode', P, seriesOf(P, p => Object.entries(p.by_rcode || {}), 6), fmt);
  chart('c-qtype', P, seriesOf(P, p => Object.entries(p.by_type || {}), 6), fmt);

  const sel = state.selected != null && P[state.selected] ? P[state.selected] : (state.selected == null ? state.now : null);
  const view = sel || state.now;
  $('when').textContent = view ? '— ' + (state.selected == null ? 'latest window' : new Date(view.t).toLocaleString()) : '';
  const qcols = [{ h: 'client', f: r => r.client }, { h: 'domain', f: r => r.domain }, { h: 'q/s', n: 1, f: r => fmt(r.qps) }];
  const fcols = [{ h: 'client', f: r => r.client }, { h: 'domain', f: r => r.domain }, { h: 'rcode', f: r => r.rcode }, { h: 'fail/s', n: 1, f: r => fmt(r.qps) }];
  table('t-pairs', view ? view.top_pairs || [] : [], qcols);
  table('t-fail', view ? view.fail_pairs || [] : [], fcols);
}

$('range').value = state.range;
$('range').addEventListener('change', e => { state.range = e.target.value; state.selected = null; refresh(); });
$('latest').addEventListener('click', () => { state.selected = null; render(); });
refresh();
setInterval(refresh, REFRESH_MS);
