// Guards on the mint command itself. External review, 2026-08-03: minting into a FRESH output folder
// bypassed the serial-overlap check entirely, because that check only scanned manifests in the chosen
// directory. A v2 card minted at serial 101 reported fully valid, and the shipped apps then refused it as
// counterfeit because the v1 card table covers 101-400. That combination can brick a whole print run
// before a single card is funded.
//
// Run: node test-mint-guards.mjs
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, existsSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { KNOWN_BATCH } from './known-batch.js';
import { knownCardStatus, buildRecord, parseAndVerifyCard, pubOfScalar, halfScalar, b64u } from './core.js';

let pass = 0, fail = 0;
const ok = (n, c, d) => { c ? pass++ : (fail++, console.log('FAIL: ' + n + (d !== undefined ? '\n      ' + d : ''))); };

const MINT = fileURLToPath(new URL('mint-pilot-csv.mjs', import.meta.url));
const seg0 = KNOWN_BATCH.segments[0];

// run the mint into a throwaway dir; returns {ok, out}
function mintInto(count, start){
  const dir = mkdtempSync(join(tmpdir(), 'bitcard-mintguard-'));
  try {
    // capture the child's stderr instead of letting refusals print into the suite summary
    const out = execFileSync(process.execPath, [MINT, String(count), String(start), dir], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    const wrote = existsSync(dir) ? readdirSync(dir).filter(f => f.endsWith('.csv')).length : 0;
    return { ok: true, out, wrote, dir };
  } catch (e) {
    const out = String(e.stdout || '') + String(e.stderr || '');
    const wrote = existsSync(dir) ? readdirSync(dir).filter(f => f.endsWith('.csv')).length : 0;
    return { ok: false, out, wrote, dir };
  } finally {
    try { rmSync(dir, { recursive: true, force: true }); } catch (e) {}
  }
}

// ---- THE REGRESSION: a fresh folder must not let an already-published range through ----
{
  const r = mintInto(1, seg0.start);
  ok('minting into a FRESH folder at an already-published serial is refused', !r.ok,
     r.out.split('\n').slice(0, 2).join(' '));
  ok('nothing was written when refused', r.wrote === 0, r.wrote + ' csv file(s) written');
  ok('the refusal names serial reuse', /overlap|never reused/i.test(r.out), r.out.slice(0, 160));
}
// the end of a published range, and a range that straddles it, must be refused too
{
  const r = mintInto(1, seg0.end);
  ok('the LAST serial of a published range is refused', !r.ok);
}
{
  const r = mintInto(5, seg0.start - 2);   // straddles the boundary
  ok('a range straddling the start of a published batch is refused', !r.ok);
}
// reserved test-vector serials stay refused
{
  const r = mintInto(1, 4294000000);
  ok('reserved test-vector serials are refused', !r.ok, r.out.slice(0, 120));
}
// a genuinely free range still works, or the guard is just breaking minting
{
  const free = Math.max(...KNOWN_BATCH.segments.map(s => s.end)) + 10000;
  const r = mintInto(2, free);
  ok('a genuinely free range still mints', r.ok, r.out.slice(-200));
}

// ---- the other half: the card table must not be applied to a self-checking record ----
// Applying the v1 table to a v2 card is what turned a valid new card into a counterfeit.
{
  const P1 = pubOfScalar(halfScalar('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'));
  const v2 = parseAndVerifyCard('bitcard:' + b64u.encode(buildRecord(P1, seg0.start)));   // v2 card ON a covered serial
  ok('the crafted card really is v2 on a covered serial', v2.version === 2 && v2.serial === seg0.start);
  ok('a v2 record on a covered serial is NOT called a mismatch',
     knownCardStatus(v2.P1hex, v2.serial, v2.version) !== 'mismatch',
     'got ' + knownCardStatus(v2.P1hex, v2.serial, v2.version));
  // and a v1 record on a covered serial with the wrong key IS still refused
  ok('a v1 record with the wrong key on a covered serial is still refused',
     knownCardStatus(v2.P1hex, seg0.start, 1) === 'mismatch');
}

console.log('\n' + (fail === 0 ? 'MINT GUARDS OK (' + pass + ' passed)' : 'MINT GUARDS FAILED (' + fail + ' failures)'));
process.exit(fail === 0 ? 0 : 1);
