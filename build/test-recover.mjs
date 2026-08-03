// The Python recovery tool is the LAST resort: it is what still works when bitcards.xyz, the apps and the
// company are gone. Nothing else in the suite touched it, so it could silently stop matching the JS
// derivation, or stop running at all, and we would only find out from a customer who cannot reach their coins.
//
// This suite runs the tool's own selftest AND, independently, checks that its address for the frozen
// vector equals the address core.js produces. Two implementations in two languages agreeing on the
// published vector is the only evidence that the standard is really reproducible outside this codebase.
//
// Run: node test-recover.mjs
import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { FROZEN_VECTOR, FROZEN_VECTOR_WRAP, verifyFrozenVector } from './core.js';

let pass = 0, fail = 0;
const ok = (n, c, d) => { c ? pass++ : (fail++, console.log('FAIL: ' + n + (d !== undefined ? '\n      ' + d : ''))); };

const TOOL = fileURLToPath(new URL('../recover/bitcard-recover.py', import.meta.url));
ok('recovery tool is present in the tree', existsSync(TOOL), TOOL);

// Find a python. If there is none on this machine we must NOT quietly pass: that would hide a broken tool.
let py = null;
for (const cand of ['python', 'python3', 'py']) {
  try { execFileSync(cand, ['-c', 'print(1)'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }); py = cand; break; } catch (e) {}
}
const waived = process.argv.includes('--no-python');
ok('a python interpreter is available to exercise it (or pass --no-python to waive)', py !== null || waived);

if (py && existsSync(TOOL)) {
  let out = '';
  try { out = execFileSync(py, [TOOL, '--selftest'], { encoding: 'utf8' }); }
  catch (e) { out = String(e.stdout || '') + String(e.stderr || ''); }
  ok('recovery selftest passes', /SELFTEST PASS/.test(out), out.trim().split('\n').slice(-6).join('\n      '));
  // it must not depend on OpenSSL's ripemd160, which is disabled by default on OpenSSL 3.x builds
  ok('recovery tool carries its own RIPEMD-160 (no OpenSSL dependency)', /RIPEMD-160 matches published vectors: True/.test(out));

  // CROSS-LANGUAGE: python must derive the same mainnet address and WIF as core.js for BOTH anchors.
  // A drift in either implementation shows up here and nowhere else.
  // The second anchor is the one where d1+d2 >= n. About half of all real cards land there, but the first
  // anchor never does, so without this a broken mod-n reduction would pass every other check in the tree.
  const run = (v, label) => {
    let j = '';
    try { j = execFileSync(py, [TOOL, '--part1', v.part1, '--part2', v.part2], { encoding: 'utf8' }); }
    catch (e) { j = String(e.stdout || '') + String(e.stderr || ''); }
    const addr = (j.match(/\b(bc1[a-z0-9]{20,})\b/) || [])[1];
    const wif  = (j.match(/\b([KL][1-9A-HJ-NP-Za-km-z]{50,51})\b/) || [])[1];
    ok('python derives the published mainnet address (' + label + ')',
       addr === v.addressMainnet, 'python gave ' + addr + ', spec says ' + v.addressMainnet);
    ok('python derives the published WIF (' + label + ')',
       wif === v.wifMainnet, 'python gave ' + wif + ', spec says ' + v.wifMainnet);
  };
  run(FROZEN_VECTOR, 'no wrap');
  run(FROZEN_VECTOR_WRAP, 'wraps mod n');
}

// The two anchors must genuinely differ in whether they wrap, or the second one is redundant and the
// reduction is unpinned again. Assert the property itself, not just that both addresses match.
{
  const { halfScalar } = await import('./core.js');
  const { secp256k1: secp } = await import('@noble/curves/secp256k1');
  const n = secp.CURVE.n;
  const s1 = halfScalar(FROZEN_VECTOR.part1) + halfScalar(FROZEN_VECTOR.part2);
  const s2 = halfScalar(FROZEN_VECTOR_WRAP.part1) + halfScalar(FROZEN_VECTOR_WRAP.part2);
  ok('anchor 1 does NOT wrap (d1+d2 < n)', s1 < n);
  ok('anchor 2 DOES wrap (d1+d2 >= n), so the mod-n reduction is pinned', s2 >= n);
}

const v = verifyFrozenVector();
ok('this tree still reproduces the frozen vector', v.ok, 'expected ' + v.expected + ', got ' + v.got);

console.log('\n' + (fail === 0 ? 'RECOVER OK (' + pass + ' passed)' : 'RECOVER FAILED (' + fail + ' failures)'));
process.exit(fail === 0 ? 0 : 1);
