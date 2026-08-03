// The printed-batch verifier is what certifies a print run as good. External review, 2026-08-03, finding 6:
// it decoded records by hand, so it was MORE permissive than the app. Appending one base64 character makes
// a 42-byte record the real parser refuses, yet the verifier reported all 300 cards passing and printed
// BATCH VERIFIED. A verifier must never accept what the product rejects, or it certifies unopenable cards.
//
// These build small synthetic batches in a temp dir and require the verifier to REFUSE each corruption.
// Run: node test-batch-verifier.mjs
import { execFileSync } from 'node:child_process';
import { writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as bip39 from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { secp256k1 as secp } from '@noble/curves/secp256k1';
import { hex, base64urlnopad as b64u } from '@scure/base';
import { halfScalar } from './core.js';

let pass = 0, fail = 0;
const ok = (n, c, d) => { c ? pass++ : (fail++, console.log('FAIL: ' + n + (d !== undefined ? '\n      ' + d : ''))); };

const TOOL = fileURLToPath(new URL('verify-printed-batch.mjs', import.meta.url));
const dir = mkdtempSync(join(tmpdir(), 'bitcard-batch-'));

function makeCard(serial){
  let m, d;
  for(;;){ m = bip39.generateMnemonic(wordlist, 128); try{ d = halfScalar(m); break; }catch(e){} }
  const P1 = secp.getPublicKey(hex.decode(d.toString(16).padStart(64,'0')), true);
  const rec = new Uint8Array(41);
  rec[0]=1; rec[1]=0; rec[2]=1; rec[3]=1; rec.set(P1, 4);
  rec[37]=(serial>>>24)&255; rec[38]=(serial>>>16)&255; rec[39]=(serial>>>8)&255; rec[40]=serial&255;
  return { serial, words:m.split(' '), p1Hex:hex.encode(P1), recordB64:b64u.encode(rec),
           qrUrl:'https://bitcards.xyz/app.html#'+b64u.encode(rec) };
}

// Build a batch, optionally corrupting it, and return the verifier's verdict.
function verdict(name, mutate){
  const cards = [1,2,3].map(makeCard);
  if (mutate) mutate(cards);
  const header = ['serial', ...Array.from({length:12},(_,i)=>'word_'+(i+1)), 'qr_url'].join(',');
  const csv = header + '\r\n' + cards.map(c => [c.serial, ...c.words, c.qrUrl].join(',')).join('\r\n') + '\r\n';
  const man = { network:'MAINNET', count:cards.length,
                cards: cards.map(c => ({ serial:c.serial, p1Hex:c.p1Hex, recordB64:c.recordB64, qrUrl:c.qrUrl })) };
  const cp = join(dir, name + '.csv'), mp = join(dir, name + '-QC-manifest.json');
  writeFileSync(cp, csv); writeFileSync(mp, JSON.stringify(man, null, 2));
  try { const out = execFileSync(process.execPath, [TOOL, cp, mp], { encoding:'utf8' });
        return { accepted: /BATCH VERIFIED/.test(out), out }; }
  catch (e) { return { accepted:false, out: String(e.stdout||'') }; }
}

// baseline: an honest batch MUST pass, or every negative result below is meaningless
ok('an honest batch is accepted', verdict('honest', null).accepted);

// the exact corruption from the review: one extra base64url char -> 42-byte record
ok('rejects a record with one appended character (42 bytes)',
   !verdict('appended', cs => { cs.forEach(c => { c.qrUrl += 'A'; }); }).accepted);

ok('rejects a truncated record',
   !verdict('truncated', cs => { cs.forEach(c => { c.qrUrl = c.qrUrl.slice(0, -2); }); }).accepted);

ok('rejects words that do not reproduce their own QR key',
   !verdict('swapped', cs => { const w = cs[0].words; cs[0].words = cs[1].words; cs[1].words = w; }).accepted);

ok('rejects a serial that disagrees with the one inside the record',
   !verdict('serialskew', cs => { cs[0].serial = 999; }).accepted);

ok('rejects a duplicate card key',
   !verdict('dupkey', cs => { cs[1].words = cs[0].words.slice(); cs[1].qrUrl = cs[0].qrUrl; cs[1].p1Hex = cs[0].p1Hex; }).accepted);

ok('rejects a testnet network byte in a mainnet batch',
   !verdict('testnet', cs => {
     const rec = b64u.decode(cs[0].qrUrl.slice(cs[0].qrUrl.lastIndexOf('#')+1));
     rec[1] = 1; cs[0].qrUrl = 'https://bitcards.xyz/app.html#' + b64u.encode(rec);
   }).accepted);

ok('rejects an unknown record version',
   !verdict('version', cs => {
     const rec = b64u.decode(cs[0].qrUrl.slice(cs[0].qrUrl.lastIndexOf('#')+1));
     rec[0] = 9; cs[0].qrUrl = 'https://bitcards.xyz/app.html#' + b64u.encode(rec);
   }).accepted);

ok('rejects a P1 that is not a valid curve point',
   !verdict('badpoint', cs => {
     const rec = b64u.decode(cs[0].qrUrl.slice(cs[0].qrUrl.lastIndexOf('#')+1));
     for(let i=4;i<37;i++) rec[i] = 0xff;
     cs[0].qrUrl = 'https://bitcards.xyz/app.html#' + b64u.encode(rec);
   }).accepted);

ok('rejects a QR key that disagrees with the QC manifest',
   !verdict('manifestskew', cs => { cs[0].p1Hex = '02' + 'ab'.repeat(32); }).accepted);

rmSync(dir, { recursive:true, force:true });
console.log('\n' + (fail === 0 ? 'BATCH VERIFIER OK (' + pass + ' passed)' : 'BATCH VERIFIER FAILED (' + fail + ' failures)'));
process.exit(fail === 0 ? 0 : 1);
