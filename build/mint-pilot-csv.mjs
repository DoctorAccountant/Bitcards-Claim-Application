// Mint a PRODUCTION pilot batch -> printer CSV + public QC manifest. v0.4 (no signature).
// Each card gets a fresh random Part 1. Output is SECRET (100 half-keys) and is written OUTSIDE any synced folder.
//
// Usage:  node mint-pilot-csv.mjs [count=100] [startSerial=101] [outDir]
// Default outDir = C:\Users\<you>\bitcard-mint  (a sibling of OneDrive, NOT synced).
//
// This script prints ONLY counts, checksums, and a words-masked sample â€” the mnemonics never touch stdout.
import { secp256k1 as secp } from '@noble/curves/secp256k1';
import { hmac } from '@noble/hashes/hmac';
import { sha512 } from '@noble/hashes/sha512';
import { utf8ToBytes } from '@noble/hashes/utils';
import * as bip39 from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { hex, base64urlnopad as b64u } from '@scure/base';
import { writeFileSync, mkdirSync, existsSync, readdirSync, readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import { NET } from './config.js';
// derivation AND record construction come from the ONE audited implementation, never a private copy: a
// divergence between mint and the claim app would mint cards that fund normally and cannot be opened.
// buildRecord emits v2 (46 bytes, 5-byte checksum over the first 41), so every batch from here on is
// self-checking: a mistyped card code fails its own checksum with no embedded batch table needed.
import { halfScalar, verifyFrozenVector, buildRecord, parseAndVerifyCard } from './core.js';

const APP_URL = 'https://bitcards.xyz/app.html';   // the live, audited claim app the QR opens
const n = secp.CURVE.n;

function mint(serial){
  let m1, d1;
  for(;;){ m1 = bip39.generateMnemonic(wordlist, 128); try{ d1 = halfScalar(m1); break; }catch(e){ /* ~1e-39; regenerate */ } }
  const P1 = secp.getPublicKey(hex.decode(d1.toString(16).padStart(64, '0')), true);
  const recordB64 = b64u.encode(buildRecord(P1, serial));
  // round-trip through the PRODUCTION parser before anything is written: the record a customer scans must
  // be readable by the exact code that will read it, checksum included
  const back = parseAndVerifyCard('bitcard:' + recordB64);
  if(back.P1hex !== hex.encode(P1) || back.serial !== serial || back.version !== 2){
    console.error('REFUSING: freshly built record does not round-trip through the production parser'); process.exit(1);
  }
  return { serial, words: m1.split(' '), p1Hex: hex.encode(P1), recordB64, qrUrl: APP_URL + '#' + recordB64 };
}

const COUNT = Number(process.argv[2] || 100);
const START = Number(process.argv[3] || 101);
const OUT_DIR = process.argv[4] || path.join(os.homedir(), 'bitcard-mint');

// --- argument hardening: serials are 4 unsigned bytes in the record; reject anything unsafe before generating keys ---
if (!Number.isSafeInteger(COUNT) || COUNT < 1 || COUNT > 100000) { console.error('REFUSING: count must be a whole number 1..100000, got ' + process.argv[2]); process.exit(1); }
if (!Number.isSafeInteger(START) || START < 1) { console.error('REFUSING: startSerial must be a whole positive number, got ' + process.argv[3]); process.exit(1); }
if (START + COUNT - 1 > 0xFFFFFFFF) { console.error('REFUSING: serial range exceeds uint32 (' + (START + COUNT - 1) + ' > 4294967295)'); process.exit(1); }
// serials >= 4294000000 are RESERVED for published spec/test vectors and must never appear on a real card:
// a spec example colliding with a sold card would make the example read as a forgery of it (and vice versa)
if (START + COUNT - 1 >= 4294000000) { console.error('REFUSING: serials >= 4294000000 are reserved for published test vectors'); process.exit(1); }

{ const v = verifyFrozenVector();
  if(!v.ok){ console.error('REFUSING: this tree cannot reproduce the published frozen vector (expected '+v.expected+', got '+v.got+'). Derivation has drifted; do not mint.'); process.exit(1); } }

// --- guardrail: never write secrets into a cloud-synced / version-tracked location (audit finding #3) ---
const lower = OUT_DIR.toLowerCase();
for(const bad of ['onedrive','dropbox','google drive','googledrive','\\box\\','icloud','\\.git']){
  if(lower.includes(bad)){ console.error('REFUSING: output path looks cloud-synced or tracked ('+bad+'):\n  '+OUT_DIR+'\nChoose a non-synced folder.'); process.exit(1); }
}
if(!existsSync(OUT_DIR)) mkdirSync(OUT_DIR, { recursive: true });

// --- serial-range guard: a rerun must NEVER silently replace a previous batch. Existing QC manifests in the
// output folder are the machine-readable record of what has already been allocated (the markdown ledger is the
// human copy). Overlapping a printed range would orphan those cards: the file would describe cards that do not
// exist, and two physical cards could share a serial. ---
const wantLo = START, wantHi = START + COUNT - 1;
for(const f of readdirSync(OUT_DIR)){
  if(!/-QC-manifest\.json$/.test(f)) continue;
  let prev; try{ prev = JSON.parse(readFileSync(path.join(OUT_DIR, f), 'utf8')); }catch(e){ continue; }
  const used = (prev.cards||[]).map(c=>c.serial).filter(Number.isFinite);
  if(!used.length) continue;
  const lo = Math.min(...used), hi = Math.max(...used);
  if(wantLo <= hi && wantHi >= lo){
    console.error('REFUSING: serials '+wantLo+'-'+wantHi+' overlap an existing batch ('+lo+'-'+hi+') recorded in '+f+
      '\nSerial ranges are never reused. Start after '+hi+', or move the previous batch out of this folder if it was never printed.');
    process.exit(1);
  }
}

// --- mint ---
const cards = [];
for(let i=0;i<COUNT;i++) cards.push(mint(START + i));

// --- self-verify: every row's words must reproduce the P1 embedded in that row's QR (no mispairing),
// and the serial stored inside each record must equal the serial we asked for ---
let structOK = 0; let serialOK = 0; const serials = new Set(); const p1s = new Set();
for(const c of cards){
  const P1fromWords = hex.encode(secp.getPublicKey(hex.decode(halfScalar(c.words.join(' ')).toString(16).padStart(64,'0')), true));
  const P1inRec = c.p1Hex;
  if(P1fromWords === P1inRec) structOK++;
  const rec = b64u.decode(c.recordB64);
  const recSerial = ((rec[37]<<24)|(rec[38]<<16)|(rec[39]<<8)|rec[40])>>>0;
  if(recSerial === c.serial) serialOK++;
  serials.add(c.serial); p1s.add(c.p1Hex);
}
// Every one of these is FATAL, not advisory: a printed batch that fails any of them is unrecoverable.
if(serialOK !== COUNT){ console.error('REFUSING: ' + (COUNT-serialOK) + ' record(s) carry a different serial than requested'); process.exit(1); }
if(structOK !== COUNT){ console.error('REFUSING: ' + (COUNT-structOK) + ' record(s) have words that do not reproduce their own QR key. Nothing was written.'); process.exit(1); }
if(serials.size !== COUNT){ console.error('REFUSING: duplicate serials generated ('+serials.size+' unique of '+COUNT+')'); process.exit(1); }
if(p1s.size !== COUNT){ console.error('REFUSING: duplicate card keys generated ('+p1s.size+' unique of '+COUNT+')'); process.exit(1); }

// --- CSV: serial, word_1..word_12, qr_url ---
const header = ['serial', ...Array.from({length:12},(_,i)=>'word_'+(i+1)), 'qr_url'].join(',');
const rows = cards.map(c => [c.serial, ...c.words, c.qrUrl].join(','));
const csv = header + '\r\n' + rows.join('\r\n') + '\r\n';
const csvPath = path.join(OUT_DIR, 'bitcard-pilot-'+START+'-'+(START+COUNT-1)+'.csv');
writeFileSync(csvPath, csv, { flag: 'wx' });   // exclusive: never overwrite an existing batch file

// --- public QC manifest (NO words) so you can verify printed cards later; safe to keep anywhere ---
const manifest = { network: NET.label, appUrl: APP_URL, count: COUNT, cards: cards.map(c => ({ serial:c.serial, p1Hex:c.p1Hex, recordB64:c.recordB64, qrUrl:c.qrUrl })) };
const manPath = path.join(OUT_DIR, 'bitcard-pilot-'+START+'-'+(START+COUNT-1)+'-QC-manifest.json');
writeFileSync(manPath, JSON.stringify(manifest, null, 2), { flag: 'wx' });

// --- handling note ---
writeFileSync(path.join(OUT_DIR, 'HANDLING.txt'),
  'This folder contains SECRET card half-keys (the CSV word columns).\r\n' +
  '- Send the CSV to the printer over an ENCRYPTED channel only.\r\n' +
  '- After the print run is confirmed good, DESTROY this folder (secure delete).\r\n' +
  '- Never copy it into OneDrive/Dropbox/Google Drive/git.\r\n' +
  '- The QC-manifest.json holds only PUBLIC data (no words) and is safe to keep.\r\n');

const csvHash = createHash('sha256').update(csv).digest('hex');
console.log('=== Bitcard pilot mint ('+NET.label+') ===');
console.log('cards:            '+COUNT+'  serials '+START+'..'+(START+COUNT-1));
console.log('unique serials:   '+serials.size+'/'+COUNT+(serials.size===COUNT?' OK':'  <-- COLLISION'));
console.log('unique Part-1:    '+p1s.size+'/'+COUNT+(p1s.size===COUNT?' OK':'  <-- COLLISION'));
console.log('words<->QR check:  '+structOK+'/'+COUNT+(structOK===COUNT?' OK (no card can be mispaired)':'  <-- MISMATCH'));
console.log('CSV sha256:       '+csvHash);
console.log('CSV:              '+csvPath);
console.log('QC manifest:      '+manPath);
console.log('\nsample row (words masked): '+[cards[0].serial, ...Array(12).fill('***'), cards[0].qrUrl].join(','));
console.log('\n*** The CSV holds 100 secret half-keys. Encrypt to send; destroy after the run. See HANDLING.txt. ***');
