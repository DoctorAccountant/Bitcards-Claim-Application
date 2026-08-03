// Merge pilot mint batches into ONE printer CSV and independently RE-VERIFY every row end to end.
// Verification per row: 12 words -> scalar -> public key MUST equal the P1 inside that row's QR record;
// record serial must equal the CSV serial; network byte must be mainnet; version must be 1.
// Output adds an inventory `sku` column (boss scheme LINE-VARIANT-BATCH-SEQUENCE) after qr_url.
// Usage: node merge-pilot-csv.mjs <out.csv> <skuPrefix> <in1.csv> [in2.csv ...]
import { secp256k1 as secp } from '@noble/curves/secp256k1';
import { hmac } from '@noble/hashes/hmac';
import { sha512 } from '@noble/hashes/sha512';
import { utf8ToBytes } from '@noble/hashes/utils';
import * as bip39 from '@scure/bip39';
import { hex, base64urlnopad as b64u } from '@scure/base';
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
// Derivation comes from the ONE audited implementation, never a private copy. A divergence between this
// script and the claim app would pass this script's own self-check and produce cards that fund normally
// and cannot be opened, long after the maker copy is destroyed.
// parseAndVerifyCard is the production parser: it enforces length, version (v1 or v2), network, script,
// kdf, curve-point validity and the v2 checksum. Hand-slicing bytes here would make this script more
// permissive than the app (external review finding 6), certifying printer files the app rejects.
import { halfScalar, verifyFrozenVector, parseAndVerifyCard } from './core.js';

const [out, skuPrefix, ...ins] = process.argv.slice(2);
if (!out || !skuPrefix || !ins.length) { console.error('usage: node merge-pilot-csv.mjs <out.csv> <skuPrefix> <in1.csv> ...'); process.exit(1); }
if (out.toLowerCase().includes('onedrive') || out.toLowerCase().includes('sharepoint')) { console.error('REFUSING: output must not be cloud-synced'); process.exit(1); }

{ const v = verifyFrozenVector();
  if (!v.ok) { console.error('REFUSING: this tree cannot reproduce the published frozen vector (expected ' + v.expected + ', got ' + v.got + '). Derivation has drifted; do not build a printer file.'); process.exit(1); } }

const rows = []; const serials = new Set(); const p1s = new Set();
for (const f of ins) {
  const lines = readFileSync(f, 'utf8').trim().split(/\r?\n/);
  const header = lines.shift();
  if (!header.startsWith('serial,word_1')) throw new Error(f + ': unexpected header');
  for (const line of lines) {
    const c = line.split(',');
    if (c.length !== 14) throw new Error(f + ': bad column count: ' + line.slice(0, 20));
    const serial = Number(c[0]); const words = c.slice(1, 13); const qrUrl = c[13];
    // decode the record through the PRODUCTION parser and verify everything about this row.
    // parseAndVerifyCard is built for mainnet here, so a testnet or malformed record throws.
    const frag = qrUrl.slice(qrUrl.lastIndexOf('#') + 1);
    let parsed;
    try { parsed = parseAndVerifyCard('bitcard:' + frag); }
    catch (e) { throw new Error('serial ' + serial + ': record rejected by the production parser: ' + e.message); }
    const p1InQR = parsed.P1hex;
    if (parsed.serial !== serial) throw new Error('serial mismatch: csv ' + serial + ' vs record ' + parsed.serial);
    const p1FromWords = hex.encode(secp.getPublicKey(hex.decode(halfScalar(words.join(' ')).toString(16).padStart(64, '0')), true));
    if (p1FromWords !== p1InQR) throw new Error('serial ' + serial + ': WORDS DO NOT MATCH QR');
    if (!qrUrl.startsWith('https://bitcards.xyz/app.html#')) throw new Error('serial ' + serial + ': unexpected URL');
    if (serials.has(serial)) throw new Error('duplicate serial ' + serial);
    if (p1s.has(p1InQR)) throw new Error('duplicate key at serial ' + serial);
    serials.add(serial); p1s.add(p1InQR);
    rows.push({ serial, words, qrUrl, p1Hex: p1InQR, recordB64: frag });
  }
}
rows.sort((a, b) => a.serial - b.serial);

const header = ['serial', ...Array.from({ length: 12 }, (_, i) => 'word_' + (i + 1)), 'qr_url', 'sku'].join(',');
const body = rows.map((r, i) => [r.serial, ...r.words, r.qrUrl, skuPrefix + '-' + String(i + 1).padStart(6, '0')].join(','));
const csv = header + '\r\n' + body.join('\r\n') + '\r\n';
// exclusive: a rerun must never silently replace the printer file whose SHA-256 is recorded in the ledger
writeFileSync(out, csv, { flag: 'wx' });

const manifest = {
  network: 'MAINNET', appUrl: 'https://bitcards.xyz/app.html', count: rows.length, skuPrefix,
  cards: rows.map((r, i) => ({ serial: r.serial, sku: skuPrefix + '-' + String(i + 1).padStart(6, '0'), p1Hex: r.p1Hex, recordB64: r.recordB64, qrUrl: r.qrUrl }))
};
const manPath = out.replace(/\.csv$/i, '') + '-QC-manifest.json';
writeFileSync(manPath, JSON.stringify(manifest, null, 2), { flag: 'wx' });

console.log('=== merged + independently re-verified ===');
console.log('rows:            ' + rows.length + ' (serials ' + rows[0].serial + '..' + rows[rows.length - 1].serial + ')');
console.log('every row re-checked through the production parser: words->key == QR key, serial match, mainnet, version + checksum, URL, no duplicates');
console.log('sku range:       ' + skuPrefix + '-000001 .. ' + skuPrefix + '-' + String(rows.length).padStart(6, '0'));
console.log('CSV sha256:      ' + createHash('sha256').update(csv).digest('hex'));
console.log('CSV:             ' + out);
console.log('QC manifest:     ' + manPath);
