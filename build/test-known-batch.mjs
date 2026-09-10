// The retrofitted checksum. External review, 2026-08-03, finding 2: a v1 record has no integrity check, so
// about 40% of single-character corruptions of a hand-typed card code still decode to a VALID record with a
// DIFFERENT valid public key. The giving flow would then show a normal deposit address that no key opens,
// the giver funds it, and the loss only surfaces when the recipient cannot claim.
//
// We cannot add a checksum to printed cards. We can check them against the keys we actually printed.
// Run: node test-known-batch.mjs
import { knownCardStatus, parseAndVerifyCard, normCardInput, buildRecord, pubOfScalar, halfScalar, hexlib, b64u } from './core.js';
import { KNOWN_BATCH } from './known-batch.js';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

let pass = 0, fail = 0;
const ok = (n, c, d) => { c ? pass++ : (fail++, console.log('FAIL: ' + n + (d !== undefined ? '\n      ' + d : ''))); };
const CARD_101 = 'AQABAQNeyFBDvBKLzkvd64SOllZZHCuKXg4IsZ9iuQLKISgIOwAAAGU';
const CARD_101_BOUNDARY_MUTATION = 'AQABAQNeyFBDvBKLzkvd64SOllZZHCuKXg4IsZ9iuQLKISgIOBAAAGU';

ok('the table has at least one segment', Array.isArray(KNOWN_BATCH.segments) && KNOWN_BATCH.segments.length > 0);
for (const s of (KNOWN_BATCH.segments || [])) {
  const len = (() => { try { return Buffer.from(s.hashes, 'base64').length; } catch (e) { return -1; } })();
  ok('segment ' + s.start + '-' + s.end + ' blob matches its serial count',
     len === (s.end - s.start + 1) * KNOWN_BATCH.trunc, 'blob ' + len + ' bytes');
}

// The 300 printed v1 cards are a permanent compatibility obligation. Pin the exact public table bytes so
// an empty, truncated, or accidentally regenerated table cannot turn all issued cards into UNKNOWN while
// a shape-only test stays green. Future v2 cards do not depend on this table.
{
  const legacy = (KNOWN_BATCH.segments || []).find(s => s.start === 101 && s.end === 400);
  const blob = legacy ? Buffer.from(legacy.hashes, 'base64') : Buffer.alloc(0);
  ok('legacy v1 table uses the frozen five-byte entries', KNOWN_BATCH.trunc === 5);
  ok('legacy v1 table covers exactly issued serials 101-400', !!legacy);
  ok('legacy v1 table has exactly 300 entries', blob.length === 1500, 'blob ' + blob.length + ' bytes');
  ok('legacy v1 table bytes match the frozen issued batch',
     createHash('sha256').update(blob).digest('hex') === '4c24f56a1f3d45036cfce9f2e62b66755b34a84f161a48dd10c840892a2332a1');
}

// Frozen reproduction from the independent review: one base64url substitution changes both P1 and serial,
// escaping the known serial range. The table must call this UNKNOWN (not "caught as a mismatch"), while the
// official funding policy refuses it. Claim/recovery remains available so old third-party v1 cards are not bricked.
{
  const original = parseAndVerifyCard('bitcard:' + CARD_101);
  const changed = parseAndVerifyCard('bitcard:' + CARD_101_BOUNDARY_MUTATION);
  ok('boundary fixture starts as an issued v1 card', knownCardStatus(original.P1hex, original.serial) === 'ok');
  ok('one-character boundary fixture changes the key', changed.P1hex !== original.P1hex);
  ok('one-character boundary fixture changes the serial', changed.serial !== original.serial);
  ok('boundary escape is honestly classified UNKNOWN', knownCardStatus(changed.P1hex, changed.serial) === 'unknown');
  ok('boundary escape is refused for funding', !(changed.version !== 1 || knownCardStatus(changed.P1hex, changed.serial) === 'ok'));
}
// segments must be sorted and non-overlapping, or a serial could resolve to the wrong card's hash
{
  const segs = (KNOWN_BATCH.segments || []).slice();
  let sane = true;
  for (let i = 1; i < segs.length; i++) if (segs[i].start <= segs[i-1].end) sane = false;
  ok('segments are ordered and do not overlap', sane);
}

// ---- against the real minted batch, if this machine has it ----
// Check EVERY manifest present, not just the first: a second print run is exactly when a table that only
// covered one batch would start silently rejecting real cards.
const MANS = (process.env.BITCARD_MANIFEST ? [process.env.BITCARD_MANIFEST] : [
  'C:/Users/Cameron/bitcard-mint/bitcard-print-300-QC-manifest.json',
  'C:/Users/Cameron/bitcard-mint/bitcard-print-300-b2-QC-manifest.json',
]);
const loaded = [];
for (const p of MANS) { try { loaded.push(JSON.parse(readFileSync(p, 'utf8'))); } catch (e) {} }
const man = loaded.length ? { cards: loaded.flatMap(m => m.cards) } : null;
if (man) {
  console.log('  checking ' + loaded.length + ' manifest(s), ' + man.cards.length + ' cards');
  let good = 0, bad = 0;
  for (const c of man.cards) (knownCardStatus(c.p1Hex, c.serial) === 'ok' ? good++ : bad++);
  ok('every minted card is recognized by the embedded table', bad === 0, bad + ' of ' + man.cards.length + ' not recognized');

  // THE CASE THAT MATTERS: flip the compressed-point prefix, the reviewer's own example. This is a valid
  // curve point and a structurally valid record, so nothing else in the product would object.
  const c0 = man.cards[0];
  const flipped = (c0.p1Hex.startsWith('02') ? '03' : '02') + c0.p1Hex.slice(2);
  ok('a prefix-flipped key on a real serial is REJECTED', knownCardStatus(flipped, c0.serial) === 'mismatch');

  // and a single-character corruption of the actual card code, end to end through the parser
  let refusedForFunding = 0, mismatches = 0, unknowns = 0, parsedAsValid = 0;
  const url = c0.qrUrl;
  const frag = url.slice(url.lastIndexOf('#') + 1);
  const ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  for (let i = 0; i < frag.length; i++) {
    for (const ch of ALPHA) {
      if (ch === frag[i]) continue;
      const bad = frag.slice(0, i) + ch + frag.slice(i + 1);
      let p; try { p = parseAndVerifyCard(normCardInput('bitcard:' + bad)); } catch (e) { continue; }
      parsedAsValid++;                                   // the record survived: this is the dangerous set
      const status = knownCardStatus(p.P1hex, p.serial);
      if (status === 'mismatch') mismatches++;
      if (status === 'unknown') unknowns++;
      // This is the source-level policy. The UI suite independently drives the production bundle and proves
      // the same policy is enforced at every Setup/Give entry point, so this test cannot substitute for it.
      if (p.version !== 1 || status === 'ok') { /* eligible */ } else refusedForFunding++;
    }
  }
  ok('single-char corruptions that still parse are all ineligible for funding (' + refusedForFunding + '/' + parsedAsValid + ')',
     parsedAsValid > 0 && refusedForFunding === parsedAsValid, (parsedAsValid - refusedForFunding) + ' would be eligible');
  ok('the test records boundary escapes as UNKNOWN instead of pretending the table caught them', unknowns > 0,
     'no unknown mutations were observed; this no longer exercises the boundary condition');
  console.log('  note: ' + parsedAsValid + ' of ' + (frag.length * 63) +
              ' substitutions parsed: ' + mismatches + ' known-serial mismatches, ' + unknowns +
              ' boundary escapes. Both are refused for funding; unknown v1 remains claimable for recovery.');
} else {
  console.log('  (no minted manifest on this machine; skipping the real-batch assertions)');
}

// ---- Unknown v1 remains parseable/claimable for the open standard, but the official reference apps must not
// use it to create a NEW funding address because v1 has no checksum and the table cannot distinguish a boundary
// typo from a third-party card. Future third-party cards should use v2. ----
{
  const d = halfScalar('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about');
  const P1 = pubOfScalar(d);
  const segs = KNOWN_BATCH.segments;
  const outside = Math.max(...segs.map(s => s.end)) + 5000;
  const v1 = buildRecord(P1, outside).slice(0, 41); v1[0] = 0x01;
  const uri = 'bitcard:' + b64u.encode(v1);
  const p = parseAndVerifyCard(uri);
  ok('a card outside our minted range is UNKNOWN, not rejected', knownCardStatus(p.P1hex, p.serial) === 'unknown');
  ok('an unknown v1 card is not eligible for official-app funding',
     !(p.version !== 1 || knownCardStatus(p.P1hex, p.serial) === 'ok'));
  // The GAP between two allocated batches is the case a single-range table got wrong: a serial there must
  // be unknown, never silently indexed into a neighbouring batch's hashes.
  if (segs.length > 1) {
    const gap = segs[0].end + 1;
    ok('a serial in the gap between batches is UNKNOWN (' + gap + ')', knownCardStatus(p.P1hex, gap) === 'unknown');
    ok('the gap is real (batches are not adjacent)', segs[1].start > segs[0].end + 1);
  }
  ok('serial 0 is treated as unknown, not an index underflow', knownCardStatus(p.P1hex, 0) === 'unknown');
  ok('a negative serial cannot index the table', knownCardStatus(p.P1hex, -1) === 'unknown');
  ok('a non-integer serial cannot index the table', knownCardStatus(p.P1hex, 1.5) === 'unknown');
  ok('garbage key material is a mismatch, never a crash', knownCardStatus('zz', segs[0].start) === 'mismatch');
}

console.log('\n' + (fail === 0 ? 'KNOWN BATCH OK (' + pass + ' passed)' : 'KNOWN BATCH FAILED (' + fail + ' failures)'));
process.exit(fail === 0 ? 0 : 1);
