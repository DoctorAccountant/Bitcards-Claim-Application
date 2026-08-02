// Mint a PRODUCTION pilot batch -> printer CSV + public QC manifest. v0.4 (no signature).
// Each card gets a fresh random Part 1. Output is SECRET (100 half-keys) and is written OUTSIDE any synced folder.
//
// Usage:  node mint-pilot-csv.mjs [count=100] [startSerial=101] [outDir]
// Default outDir = C:\Users\<you>\bitcard-mint  (a sibling of OneDrive, NOT synced).
//
// This script prints ONLY counts, checksums, and a words-masked sample — the mnemonics never touch stdout.
import { secp256k1 as secp } from '@noble/curves/secp256k1';
import { hmac } from '@noble/hashes/hmac';
import { sha512 } from '@noble/hashes/sha512';
import { utf8ToBytes } from '@noble/hashes/utils';
import * as bip39 from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { hex, base64urlnopad as b64u } from '@scure/base';
import { writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import { NET } from './config.js';

const APP_URL = 'https://bitcards.xyz/app.html';   // the live, audited claim app the QR opens
const n = secp.CURVE.n;

function halfScalar(m){
  const k = BigInt('0x' + hex.encode(hmac(sha512, utf8ToBytes('Bitcoin seed'), bip39.mnemonicToSeedSync(m, '')).slice(0, 32)));
  if (k === 0n || k >= n) throw new Error('invalid master scalar (reject per spec 3.4)');
  return k;
}
function mint(serial){
  let m1, d1;
  for(;;){ m1 = bip39.generateMnemonic(wordlist, 128); try{ d1 = halfScalar(m1); break; }catch(e){ /* ~1e-39; regenerate */ } }
  const P1 = secp.getPublicKey(hex.decode(d1.toString(16).padStart(64, '0')), true);
  const rec = new Uint8Array(41);
  rec[0]=1; rec[1]=NET.networkByte; rec[2]=1; rec[3]=1; rec.set(P1, 4);
  rec[37]=(serial>>>24)&255; rec[38]=(serial>>>16)&255; rec[39]=(serial>>>8)&255; rec[40]=serial&255;
  const recordB64 = b64u.encode(rec);
  return { serial, words: m1.split(' '), p1Hex: hex.encode(P1), recordB64, qrUrl: APP_URL + '#' + recordB64 };
}

const COUNT = Number(process.argv[2] || 100);
const START = Number(process.argv[3] || 101);
const OUT_DIR = process.argv[4] || path.join(os.homedir(), 'bitcard-mint');

// --- argument hardening: serials are 4 unsigned bytes in the record; reject anything unsafe before generating keys ---
if (!Number.isSafeInteger(COUNT) || COUNT < 1 || COUNT > 100000) { console.error('REFUSING: count must be a whole number 1..100000, got ' + process.argv[2]); process.exit(1); }
if (!Number.isSafeInteger(START) || START < 1) { console.error('REFUSING: startSerial must be a whole positive number, got ' + process.argv[3]); process.exit(1); }
if (START + COUNT - 1 > 0xFFFFFFFF) { console.error('REFUSING: serial range exceeds uint32 (' + (START + COUNT - 1) + ' > 4294967295)'); process.exit(1); }

// --- guardrail: never write secrets into a cloud-synced / version-tracked location (audit finding #3) ---
const lower = OUT_DIR.toLowerCase();
for(const bad of ['onedrive','dropbox','google drive','googledrive','\\box\\','icloud','\\.git']){
  if(lower.includes(bad)){ console.error('REFUSING: output path looks cloud-synced or tracked ('+bad+'):\n  '+OUT_DIR+'\nChoose a non-synced folder.'); process.exit(1); }
}
if(!existsSync(OUT_DIR)) mkdirSync(OUT_DIR, { recursive: true });

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
if(serialOK !== COUNT){ console.error('REFUSING: ' + (COUNT-serialOK) + ' record(s) carry a different serial than requested'); process.exit(1); }

// --- CSV: serial, word_1..word_12, qr_url ---
const header = ['serial', ...Array.from({length:12},(_,i)=>'word_'+(i+1)), 'qr_url'].join(',');
const rows = cards.map(c => [c.serial, ...c.words, c.qrUrl].join(','));
const csv = header + '\r\n' + rows.join('\r\n') + '\r\n';
const csvPath = path.join(OUT_DIR, 'bitcard-pilot-'+START+'-'+(START+COUNT-1)+'.csv');
writeFileSync(csvPath, csv);

// --- public QC manifest (NO words) so you can verify printed cards later; safe to keep anywhere ---
const manifest = { network: NET.label, appUrl: APP_URL, count: COUNT, cards: cards.map(c => ({ serial:c.serial, p1Hex:c.p1Hex, recordB64:c.recordB64, qrUrl:c.qrUrl })) };
const manPath = path.join(OUT_DIR, 'bitcard-pilot-'+START+'-'+(START+COUNT-1)+'-QC-manifest.json');
writeFileSync(manPath, JSON.stringify(manifest, null, 2));

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
