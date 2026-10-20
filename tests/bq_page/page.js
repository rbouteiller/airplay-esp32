// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

/*
 * The /bq page draws each filter with its own JavaScript port of the
 * firmware's designs. This lifts that code out of data/www/bq.html, designs
 * every setting designs.c printed, and checks the page would draw the filter
 * the firmware plays: the same five coefficients, and the same curve on the
 * page's own frequency grid.
 *
 * Usage: node page.js <bq.html> < designs.jsonl
 */

'use strict';
const fs = require('fs');
const vm = require('vm');

const html = fs.readFileSync(process.argv[2], 'utf8');

/* A top-level function, braces balanced from its first line. */
function lift(name) {
  const at = html.search(new RegExp('^function ' + name + '\\(', 'm'));
  if (at < 0) throw new Error('bq.html has no function ' + name);
  let depth = 0;
  for (let i = html.indexOf('{', at); i < html.length; i++) {
    if (html[i] === '{') depth++;
    else if (html[i] === '}' && --depth === 0) return html.slice(at, i + 1);
  }
  throw new Error('unbalanced function ' + name);
}
/* A top-level var statement, by the name it starts with. */
function liftVar(name) {
  const m = new RegExp('^var ' + name + '=[^;]*(?:;[^\\n]*)?$', 'm').exec(html);
  if (!m) throw new Error('bq.html has no var ' + name);
  return m[0];
}

const code = [
  liftVar('T_BYPASS'), liftVar('S_BW1'), liftVar('F_MIN'), liftVar('P'),
  ...['clamp', 'eqBq', 'shelfG', 'shelfBq', 'cheby', 'bilinear', 'passBq',
      'bandBq', 'notchBq', 'unity', 'designBq', 'designShape', 'response',
      'magDb', 'sweep'].map(lift),
].join('\n');
const page = vm.createContext({Math, isFinite});
vm.runInContext(code, page);

const designs = fs.readFileSync(0, 'utf8').trim().split('\n').map(JSON.parse);
const KEYS = ['b0', 'b1', 'b2', 'a1', 'a2'];
/* Half a step of the part's 5.27 words: closer than that, both round to the
 * same coefficient (the Chebyshev prototype is computed by another route
 * here, which costs a few parts in 1e9). */
const HALF_LSB = 0.5 / 2 ** 27;
let failed = 0, worstCoeff = 0, worstDb = 0, worstAt = null, worstDbAt = null;
const byRegion = {low: 0, mid: 0, high: 0};

for (const d of designs) {
  const b = {type: d.type, sub: d.sub, freq: d.freq, q: d.q, bw: d.bw,
             gain: d.gain, ripple: d.ripple, invert: d.invert, coeff: []};
  const o = page.designBq(b, d.fs);
  const js = KEYS.map((k) => o[k]);

  let err = 0;
  for (let i = 0; i < 5; i++) {
    err = Math.max(err, Math.abs(js[i] - d.c[i]) / Math.max(1, Math.abs(d.c[i])));
  }
  if (err > worstCoeff) { worstCoeff = err; worstAt = d; }

  /* The curve as the page draws it, against the firmware's coefficients on
   * the same grid. */
  const c = {b0: d.c[0], b1: d.c[1], b2: d.c[2], a1: d.c[3], a2: d.c[4]};
  const drawn = page.sweep([o], d.fs, page.magDb, false).total;
  const played = page.sweep([c], d.fs, page.magDb, false).total;
  let dbErr = 0;
  for (let i = 0; i < drawn.length; i++) {
    dbErr = Math.max(dbErr, Math.abs(drawn[i] - played[i]));
  }
  const region = d.freq < 500 ? 'low' : d.freq < 5000 ? 'mid' : 'high';
  byRegion[region] = Math.max(byRegion[region], dbErr);
  if (dbErr > worstDb) { worstDb = dbErr; worstDbAt = d; }

  if (err > HALF_LSB || dbErr > 1e-6) {
    failed++;
    if (failed <= 20) {
      console.log(`FAIL type ${d.type} sub ${d.sub} ${d.freq} Hz Q${d.q} ` +
                  `${d.gain} dB bw ${d.bw} at ${d.fs}: coefficients off by ` +
                  `${err.toExponential(2)}, curve by ${dbErr.toFixed(6)} dB`);
    }
  }
}

const name = (d) => d ? `type ${d.type} sub ${d.sub} ${d.freq} Hz at ${d.fs}` : '-';
console.log(`  ${designs.length} designs: coefficients agree to ` +
            `${worstCoeff.toExponential(1)} (${name(worstAt)})`);
console.log(`  drawn vs played: low ${byRegion.low.toExponential(1)} dB, ` +
            `mid ${byRegion.mid.toExponential(1)} dB, high ` +
            `${byRegion.high.toExponential(1)} dB (worst ${name(worstDbAt)})`);
if (failed) {
  console.log(`${failed} design(s) drawn differently from how they play`);
  process.exit(1);
}
console.log('The page draws every filter the firmware plays');
