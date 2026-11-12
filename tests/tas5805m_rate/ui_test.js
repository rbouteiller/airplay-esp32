// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// Run the actual page against coefficients and rates emitted by the driver.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const fixture = JSON.parse(fs.readFileSync(0, 'utf8'));
const html = fs.readFileSync(path.join(__dirname, '../../data/www/bq.html'), 'utf8');
const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];
const elements = new Map();
const context = vm.createContext({
  window: { addEventListener() {} },
  document: {
    getElementById(id) {
      if (!elements.has(id)) elements.set(id, {
        id, style: {}, checked: true,
        classList: { toggle() {}, add() {}, remove() {} },
      });
      return elements.get(id);
    },
  },
});
vm.runInContext(script, context);
const run = (source) => vm.runInContext(source, context);
context.data = structuredClone(fixture);

const rates = [fixture.rate, fixture.rate % 11025 === 0 ? 88200 : 96000];
assert.deepEqual(fixture.amps.map((amp) => amp.rate), rates);
assert.equal(run('fs(0)'), rates[0]);
assert.equal(run('fs(1)'), rates[1]);
run('amp=1; drawTabs();');
assert.equal(run('fs()'), rates[1]);
assert.equal(elements.get('sub').textContent, `15 biquads per output at ${rates[1]} Hz`);

// Independent complex response of the driver's first packed section. This
// checks every plotted point, including the phase-aware sum, at physical Hz.
function transfer(coeff, hz, rate) {
  const w = 2 * Math.PI * hz / rate;
  const c1 = Math.cos(w), s1 = Math.sin(w);
  const c2 = Math.cos(2 * w), s2 = Math.sin(2 * w);
  const nr = coeff[0] + coeff[1] * c1 + coeff[2] * c2;
  const ni = -coeff[1] * s1 - coeff[2] * s2;
  const dr = 1 - coeff[3] * c1 - coeff[4] * c2;
  const di = coeff[3] * s1 + coeff[4] * s2;
  const power = dr * dr + di * di;
  return { re: (nr * dr + ni * di) / power, im: (ni * dr - nr * di) / power };
}
function db(h) { return 20 * Math.log10(Math.hypot(h.re, h.im)); }

run('drawGraph=function(cv,sweeps,lo,hi,step,fmt,totalsOnly,extras){captured={sweeps:sweeps,extras:extras};};');
for (const selected of [0, 1]) {
  context.amp = selected;
  run('plotAll();');
  const { sweeps, extras } = context.captured;
  const top = Math.min(20000, rates[0] / 2, rates[1] / 2);
  assert.equal(sweeps.length, 2);
  assert.ok(sweeps.every((sweep) => sweep.f1 === top));
  for (let i = 0; i <= sweeps[0].n; i++) {
    const hz = 20 * Math.pow(top / 20, i / sweeps[0].n);
    let re = 0, im = 0;
    for (let amp = 0; amp < 2; amp++) {
      const h = transfer(fixture.amps[amp].channels[0][0].coeff, hz, rates[amp]);
      assert.ok(Math.abs(sweeps[amp].total[i] - db(h)) < 1e-8,
        `amp ${amp} response uses its DSP rate at ${hz} Hz`);
      re += h.re;
      im += h.im;
    }
    assert.ok(Math.abs(extras[0].v[i] - db({ re, im })) < 1e-8,
      `combined response uses physical Hz at ${hz} Hz`);
  }
}

// Opening the page fits every raw section, including invisible amplifier
// tabs. Applying those fitted shapes must preserve the original 2 kHz cut.
assert.equal(run('autoShape()'), 0);
for (const amp of context.data.amps) {
  for (const channel of amp.channels) {
    assert.equal(channel[0].type, 1);
    assert.ok(Math.abs(channel[0].freq - 2000) < 1);
  }
}
run('storeRows=function(){}; show=function(){}; postSeq=function(bodies){applied=bodies;return Promise.resolve(true);}; apply();');
assert.equal(context.applied.length, 2);
const roundtrip = context.applied.map(({ dev, filters }) =>
  `${dev} ${filters[0].freq} ${filters[0].q} ${filters[0].gain}`).join('\n');

// Headroom also examines invisible amps. Give the second amp a raw 6 kHz
// boost and mute the first so a wrong rate cannot hide behind another peak.
context.data = structuredClone(fixture);
run(`
data.amps[0].mutes=[true,true];
var peak=eqBq(12,6000,5,fs(1));
data.amps[1].channels[0][0].coeff=[peak.b0,peak.b1,peak.b2,peak.a1,peak.a2];
gainInfo={db:0,min_db:-30,recommended:[{volts:5,db:0}]};
`);
// This page reports the boost in showHeadroom(), which prints the level but
// not where it peaks, so check the peak it finds directly.
for (const selected of [0, 1]) {
  context.amp = selected;
  run(`showHeadroom();
var cs=activeChains(),k,r;peakHz=0;peakDb=-Infinity;
for(k=0;k<cs.length;k++){
  r=chainPeak(sectionsOf(cs[k].c,cs[k].rate),cs[k].rate,cs[k].g);
  if(r.db>peakDb){peakDb=r.db;peakHz=r.f;}
}`);
  assert.ok(Math.abs(context.peakHz - 6000) < 60,
    `headroom finds the 6 kHz boost at its DSP rate (${context.peakHz} Hz)`);
}

// Older API responses and software-EQ firmware retain their global-rate
// contract; the default also remains usable before an API response arrives.
context.data = structuredClone(fixture);
for (const amp of context.data.amps) delete amp.rate;
assert.equal(run('fs(0)'), fixture.rate);
assert.equal(run('fs(1)'), fixture.rate);
context.data = null;
assert.equal(run('fs()'), 48000);

process.stdout.write(`${roundtrip}\n`);
process.stderr.write(`UI rate/response/Apply checks passed at ${fixture.rate} Hz I2S\n`);
