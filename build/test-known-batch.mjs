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

let pass = 0, fail = 0;
const ok = (n, c, d) => { c ? pass++ : (fail++, console.log('FAIL: ' + n + (d !== undefined ? '\n      ' + d : ''))); };

ok('the batch table covers a contiguous range', KNOWN_BATCH.endSerial > KNOWN_BATCH.startSerial);
ok('the table is the size the range implies',
   b64uLen() === (KNOWN_BATCH.endSerial - KNOWN_BATCH.startSerial + 1) * KNOWN_BATCH.trunc,
   'blob is a different length than the serial range');
function b64uLen(){ try{ return Buffer.from(KNOWN_BATCH.hashes, 'base64').length; }catch(e){ return -1; } }

// ---- against the real minted batch, if this machine has it ----
const MAN = process.env.BITCARD_MANIFEST || 'C:/Users/Cameron/bitcard-mint/bitcard-print-300-QC-manifest.json';
let man = null;
try { man = JSON.parse(readFileSync(MAN, 'utf8')); } catch (e) {}
if (man) {
  let good = 0, bad = 0;
  for (const c of man.cards) (knownCardStatus(c.p1Hex, c.serial) === 'ok' ? good++ : bad++);
  ok('every minted card is recognized by the embedded table', bad === 0, bad + ' of ' + man.cards.length + ' not recognized');

  // THE CASE THAT MATTERS: flip the compressed-point prefix, the reviewer's own example. This is a valid
  // curve point and a structurally valid record, so nothing else in the product would object.
  const c0 = man.cards[0];
  const flipped = (c0.p1Hex.startsWith('02') ? '03' : '02') + c0.p1Hex.slice(2);
  ok('a prefix-flipped key on a real serial is REJECTED', knownCardStatus(flipped, c0.serial) === 'mismatch');

  // and a single-character corruption of the actual card code, end to end through the parser
  let caught = 0, parsedAsValid = 0;
  const url = c0.qrUrl;
  const frag = url.slice(url.lastIndexOf('#') + 1);
  const ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  for (let i = 0; i < frag.length; i++) {
    for (const ch of ALPHA) {
      if (ch === frag[i]) continue;
      const bad = frag.slice(0, i) + ch + frag.slice(i + 1);
      let p; try { p = parseAndVerifyCard(normCardInput('bitcard:' + bad)); } catch (e) { continue; }
      parsedAsValid++;                                   // the record survived: this is the dangerous set
      if (knownCardStatus(p.P1hex, p.serial) !== 'ok') caught++;
    }
  }
  ok('single-char corruptions that still parse are all caught (' + caught + '/' + parsedAsValid + ')',
     parsedAsValid > 0 && caught === parsedAsValid, (parsedAsValid - caught) + ' would have slipped through');
  console.log('  note: ' + parsedAsValid + ' of ' + (frag.length * 63) +
              ' single-character corruptions decoded as a structurally valid card; all are now rejected');
} else {
  console.log('  (no minted manifest on this machine; skipping the real-batch assertions)');
}

// ---- serials outside the range must still work: this is an open standard, not a permission slip ----
{
  const d = halfScalar('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about');
  const P1 = pubOfScalar(d);
  const outside = KNOWN_BATCH.endSerial + 5000;
  const uri = 'bitcard:' + b64u.encode(buildRecord(P1, outside));
  const p = parseAndVerifyCard(uri);
  ok('a card outside our minted range is UNKNOWN, not rejected', knownCardStatus(p.P1hex, p.serial) === 'unknown');
  ok('serial 0 is treated as unknown, not an index underflow', knownCardStatus(p.P1hex, 0) === 'unknown');
  ok('a negative serial cannot index the table', knownCardStatus(p.P1hex, -1) === 'unknown');
  ok('a non-integer serial cannot index the table', knownCardStatus(p.P1hex, 1.5) === 'unknown');
  ok('garbage key material is a mismatch, never a crash', knownCardStatus('zz', KNOWN_BATCH.startSerial) === 'mismatch');
}

console.log('\n' + (fail === 0 ? 'KNOWN BATCH OK (' + pass + ' passed)' : 'KNOWN BATCH FAILED (' + fail + ' failures)'));
process.exit(fail === 0 ? 0 : 1);
