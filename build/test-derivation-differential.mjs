// RANDOM cross-implementation derivation check. External review, 2026-08-03, finding 3.
//
// The frozen vectors pin two specific mnemonics. That is necessary but not sufficient: a defect that
// derives correctly for those two and wrongly for everything else passes every other suite. The reviewer
// proved it by making halfScalar() return the right scalar for the anchors and add one to every other
// scalar; the full ten-suite gate still printed ALL SUITES PASSED, while every newly generated customer
// card would have had the wrong deposit address. Nothing in the tree compared the two implementations on
// arbitrary input, because setup-parity compares our code against itself and cannot see a shared defect.
//
// So: fresh random pairs on every run, checked against the independently written Python tool, covering
// both the wrapping and non-wrapping cases. Random by design. A fixed seed here would recreate the exact
// hole this closes.
//
// Run: node test-derivation-differential.mjs [pairs]
import { execFileSync } from 'node:child_process';
import { existsSync, writeFileSync, unlinkSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as bip39 from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { secp256k1 as secp } from '@noble/curves/secp256k1';
import { halfScalar, combine, toWIF } from './core.js';

let pass = 0, fail = 0;
const ok = (n, c, d) => { c ? pass++ : (fail++, console.log('FAIL: ' + n + (d !== undefined ? '\n      ' + d : ''))); };

const N_PAIRS = Number(process.argv[2] || 12);
const TOOL = fileURLToPath(new URL('../recover/bitcard-recover.py', import.meta.url));
const n = secp.CURVE.n;

let py = null;
for (const c of ['python', 'python3', 'py']) {
  try { execFileSync(c, ['-c', 'print(1)'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }); py = c; break; } catch (e) {}
}
const waived = process.argv.includes('--no-python');
ok('a python interpreter is available for the differential (or --no-python to waive)', py !== null || waived);
ok('the independent implementation is present', existsSync(TOOL), TOOL);

if (py && existsSync(TOOL)) {
  // Drive the tool in ONE python process: it is pure-python EC math, so a process per pair is far too slow.
  // Words go over a temp file and stdin, never argv, so they cannot leak into a process list.
  const runner = join(tmpdir(), 'bitcard-diff-runner.py');
  writeFileSync(runner, [
    'import json, sys, importlib.util',
    'spec = importlib.util.spec_from_file_location("r", sys.argv[1])',
    'm = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)',
    'out = []',
    'for p1, p2 in json.load(sys.stdin):',
    '    r = m.recover(p1, p2, mainnet=True)',
    '    out.append({"address": r["address"], "wif": r["wif"], "d": r["d_hex"]})',
    'print(json.dumps(out))',
  ].join('\n'), 'utf8');

  const pairs = [], mine = [];
  let wraps = 0;
  while (pairs.length < N_PAIRS) {
    const p1 = bip39.generateMnemonic(wordlist, 128), p2 = bip39.generateMnemonic(wordlist, 128);
    let d1, d2;
    try { d1 = halfScalar(p1); d2 = halfScalar(p2); } catch (e) { continue; }
    const wrapped = d1 + d2 >= n;
    // force coverage of BOTH sides: the reduction is exercised by about half of real cards, and a run that
    // happened to draw no wrapping pair would silently retest only the easy path
    if (wrapped) wraps++;
    if (!wrapped && pairs.length >= N_PAIRS - 2 && wraps === 0) continue;
    const out = combine(d1, d2);
    pairs.push([p1, p2]);
    mine.push({ address: out.address, wif: toWIF(out.d), d: out.d.toString(16).padStart(64, '0'), wrapped });
  }

  let theirs;
  try {
    theirs = JSON.parse(execFileSync(py, [runner, TOOL], { input: JSON.stringify(pairs), encoding: 'utf8', maxBuffer: 1 << 22 }));
  } catch (e) { theirs = null; console.log('      python runner failed: ' + String(e.stderr || e.message).slice(0, 300)); }
  try { unlinkSync(runner); } catch (e) {}

  ok('python returned a result for every pair', theirs !== null && theirs.length === pairs.length);
  if (theirs) {
    let addrBad = 0, wifBad = 0, dBad = 0;
    for (let i = 0; i < mine.length; i++) {
      if (mine[i].address !== theirs[i].address) addrBad++;
      if (mine[i].wif !== theirs[i].wif) wifBad++;
      if (BigInt('0x' + mine[i].d) !== BigInt('0x' + theirs[i].d)) dBad++;
    }
    // Never print the mnemonics on failure. Report the index so it can be reproduced deliberately.
    ok(N_PAIRS + ' random pairs: JS and python agree on the address', addrBad === 0, addrBad + ' mismatched');
    ok(N_PAIRS + ' random pairs: JS and python agree on the WIF', wifBad === 0, wifBad + ' mismatched');
    ok(N_PAIRS + ' random pairs: JS and python agree on the combined scalar', dBad === 0, dBad + ' mismatched');
    ok('the run covered at least one mod-n wrap (got ' + wraps + ' of ' + N_PAIRS + ')', wraps > 0);
    ok('the run covered at least one non-wrap', wraps < N_PAIRS);
  }
}

console.log('\n' + (fail === 0 ? 'DERIVATION DIFFERENTIAL OK (' + pass + ' passed)' : 'DERIVATION DIFFERENTIAL FAILED (' + fail + ' failures)'));
process.exit(fail === 0 ? 0 : 1);
