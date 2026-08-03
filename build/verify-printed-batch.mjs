// Re-verify an ALREADY PRINTED batch against the CURRENT, vector-anchored core.js.
//
// Why this is not redundant with the mint-time check: when these cards were minted, the mint script and
// the merge script each carried their OWN private copy of the derivation. They verified the batch against
// themselves. If any of those copies had differed from the claim app, the batch would still have passed
// its own checks and the cards would open to nothing. This re-derives every row with the one audited
// implementation that the shipped app now uses, and that implementation is pinned to published vectors.
//
// Prints COUNTS ONLY. The words never reach stdout, a log, or an error message.
// Run: node verify-printed-batch.mjs <printer.csv> <QC-manifest.json>
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { secp256k1 as secp } from '@noble/curves/secp256k1';
import { hex, base64urlnopad as b64u } from '@scure/base';
// Decode through the EXACT path the shipped app uses. This script previously sliced the record by hand,
// which accepted things the app rejects: appending one base64 character makes a 42-byte record that the
// hand-rolled slice happily read as valid while the real parser refuses it. The verifier would then
// certify a batch of cards that no customer could open. A verifier must be strictly no more permissive
// than the thing it is certifying for.
import { halfScalar, verifyFrozenVector, normCardInput, parseAndVerifyCard } from './core.js';

const [csvPath, manPath] = process.argv.slice(2);
if (!csvPath || !manPath) { console.error('usage: node verify-printed-batch.mjs <printer.csv> <QC-manifest.json>'); process.exit(1); }

const v = verifyFrozenVector();
if (!v.ok) { console.error('REFUSING: this tree cannot reproduce the published vectors; its verdict on a batch would be worthless.'); process.exit(1); }
console.log('derivation anchored to published vectors: yes (no-wrap and wrap both reproduce)');

const csv = readFileSync(csvPath, 'utf8');
console.log('csv sha256: ' + createHash('sha256').update(csv).digest('hex'));
const man = JSON.parse(readFileSync(manPath, 'utf8'));
const byserial = new Map(man.cards.map(c => [c.serial, c]));

const lines = csv.trim().split(/\r?\n/);
const head = lines.shift().split(',');
const wi = head.indexOf('word_1'), qi = head.indexOf('qr_url');
if (wi < 0 || qi < 0) { console.error('REFUSING: unexpected CSV header'); process.exit(1); }

let rows = 0, wordsMatchQR = 0, qrMatchManifest = 0, serialInRecord = 0, mainnet = 0, badSerials = [];
const p1s = new Set();
for (const line of lines) {
  const c = line.split(',');
  const serial = Number(c[0]);
  const words = c.slice(wi, wi + 12).join(' ');
  const url = c[qi];
  rows++;
  try {
    // production decode: normCardInput + parseAndVerifyCard, byte for byte what the app does
    const parsed = parseAndVerifyCard(normCardInput(url));
    const p1InQR = parsed.P1hex;
    // the one check that matters: do the PRINTED words still reproduce the PRINTED QR key today?
    const p1FromWords = hex.encode(secp.getPublicKey(hex.decode(halfScalar(words).toString(16).padStart(64, '0')), true));
    if (p1FromWords === p1InQR) wordsMatchQR++; else badSerials.push(serial);
    const m = byserial.get(serial);
    if (m && m.p1Hex === p1InQR) qrMatchManifest++;
    if (parsed.serial === serial) serialInRecord++;
    // network byte is not surfaced by the parser, which only ACCEPTS the configured network, so a
    // testnet record would already have thrown above. Re-read it anyway so the count means something.
    const rec = b64u.decode(url.slice(url.lastIndexOf('#') + 1));
    if (rec[1] === 0) mainnet++;
    p1s.add(p1InQR);
  } catch (e) { badSerials.push(serial); }
}

const all = n => n === rows ? 'OK' : 'MISMATCH';
console.log('rows:                       ' + rows);
console.log('words reproduce the QR key: ' + wordsMatchQR + '/' + rows + '  ' + all(wordsMatchQR));
console.log('QR key matches QC manifest: ' + qrMatchManifest + '/' + rows + '  ' + all(qrMatchManifest));
console.log('serial embedded in record:  ' + serialInRecord + '/' + rows + '  ' + all(serialInRecord));
console.log('mainnet network byte:       ' + mainnet + '/' + rows + '  ' + all(mainnet));
console.log('distinct card keys:         ' + p1s.size + '/' + rows + '  ' + all(p1s.size));
if (badSerials.length) console.log('SERIALS THAT FAILED: ' + badSerials.join(', '));
const good = wordsMatchQR === rows && qrMatchManifest === rows && serialInRecord === rows && mainnet === rows && p1s.size === rows;
console.log('\n' + (good
  ? 'BATCH VERIFIED against the current anchored derivation. These printed cards open correctly.'
  : 'BATCH FAILED. Do not ship these cards.'));
process.exit(good ? 0 : 1);
