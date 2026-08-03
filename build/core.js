// Bitcard shared core (spec v0.4 — open standard: cards carry NO issuer signature and no maker key exists anywhere).
// PUBLIC material only. Imported by the public claim app and the internal maker/QC tools.
// Review map: network trust rules live here (getUtxos requires ALL nodes to agree; broadcastTx requires the node to
// echo OUR locally-computed txid and a NON-accepting host to observe the tx; feeRate takes the LOWEST node estimate).
// The key scheme (§3) and record format (§4) are at the bottom. Nothing in this file touches secret words directly
// except halfScalar(), which converts 12 words to a scalar and is called by the apps.
import { secp256k1 as secp } from '@noble/curves/secp256k1';
import { hmac } from '@noble/hashes/hmac';
import { sha512 } from '@noble/hashes/sha512';
import { sha256 } from '@noble/hashes/sha256';
import { utf8ToBytes } from '@noble/hashes/utils';
import * as bip39 from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import * as btc from '@scure/btc-signer';
import { hex as hexlib, base64urlnopad as b64u, base64 as b64std, base58 } from '@scure/base';
import { NET, ACTIVE } from './config.js';        // crypto/display params (no URLs). Network layer + node URLs live in net.js.
import { KNOWN_BATCH } from './known-batch.js';   // public: truncated hashes of the keys we actually printed

export { secp, sha256, utf8ToBytes, bip39, wordlist, btc, hexlib, b64u, NET, ACTIVE };

// secp.btc network object for the active network (address encoding). Mainnet defined explicitly so we don't depend on a library export.
const BTC_MAINNET = { bech32: 'bc', pubKeyHash: 0x00, scriptHash: 0x05, wif: 0x80 };
export const BTCNET = NET.hrp === 'bc' ? BTC_MAINNET : btc.TEST_NETWORK;
export const NETWORK = NET.networkByte, SCRIPT = 0x01, KDF = 0x01; // network byte from config; P2WPKH, BIP39->BIP32-master

export const n = secp.CURVE.n;
export const $ = id => document.getElementById(id);
// textContent-only renderer: node- and user-supplied strings are never parsed as HTML (spec §10 P1 hardening).
export const log = (el, s, cls) => { const e = $(el); if(!e) return; e.textContent = ''; if(cls){ const sp = document.createElement('span'); sp.className = cls; sp.textContent = s; e.appendChild(sp); } else { e.textContent = s; } };

// ---- pure helpers shared by the online app AND the offline tool (NO network here; the network layer is net.js,
//      which the offline tool never imports, so its bundle contains zero fetch calls and zero node URLs) ----
export const isTxid = s => typeof s==='string' && /^[0-9a-fA-F]{64}$/.test(s.trim());
export const MAX_UTXOS = 500; // sanity bound on inputs a card can hold (also caps tx size / fee)
export function validateUtxos(arr){ // §7: never trust node JSON shape; reject anything that could poison the tx build
  if(!Array.isArray(arr)) throw new Error('node returned a non-array UTXO set — refusing to sign');
  if(arr.length > MAX_UTXOS) throw new Error('address has too many inputs ('+arr.length+') — refusing to sign');
  const seen = new Set();
  for(const u of arr){
    if(!u || typeof u!=='object') throw new Error('malformed UTXO entry — refusing to sign');
    if(!isTxid(u.txid)) throw new Error('malformed UTXO txid — refusing to sign');
    if(!Number.isInteger(u.vout) || u.vout < 0 || u.vout > 0xffffffff) throw new Error('malformed UTXO vout — refusing to sign');
    if(!Number.isSafeInteger(u.value) || u.value < 0) throw new Error('malformed UTXO value — refusing to sign');
    const op = u.txid+':'+u.vout; if(seen.has(op)) throw new Error('duplicate UTXO outpoint — refusing to sign'); seen.add(op);
  }
  return arr;
}
// Split a UTXO set into network-confirmed vs still-pending value. Pure function (tested in test-hardening.mjs);
// the give flow must never say "ready to give" for money the network has not confirmed yet.
export function splitConfirmed(utxos){
  let conf = 0, pend = 0;
  for(const u of utxos){ if(u.status && u.status.confirmed) conf += u.value; else pend += u.value; }
  return { conf, pend, total: conf + pend };
}
export function estVbytes(nIn){ return Math.ceil(10.5 + nIn*68 + 31); } // P2WPKH sweep, 1 output
export const MAX_FEERATE = 100; // sat/vB sanity ceiling (§7 upper bound)
// RBF bump eligibility: a replacement may claim "sped up" only if the fee can actually rise (not already at the
// ceiling) and the rebuilt transaction actually differs. Pure function so regression tests run the same code the UI does.
export function bumpEligible(lastRate, newTxid, lastTxId){
  if((lastRate||0) >= MAX_FEERATE) return { ok:false, why:'atcap' };
  if(newTxid && lastTxId && String(newTxid).toLowerCase() === String(lastTxId).toLowerCase()) return { ok:false, why:'identical' };
  return { ok:true };
}
// Network functions (fetchWithTimeout / fetchJSON / getUtxos / feeRate / broadcastTx) live in net.js.
// They are deliberately NOT in core.js so the offline tool, which imports only core.js, can never reach a node.

// ---- byte helpers ----
export function bytesToBig(b){ return BigInt('0x'+hexlib.encode(b)); }
export function bigToBytes32(x){ return hexlib.decode(x.toString(16).padStart(64,'0')); }
export function u32be(x){ return new Uint8Array([(x>>>24)&255,(x>>>16)&255,(x>>>8)&255,x&255]); }

// ---- card record + verification (spec §4) ----
// v1 (41 bytes) has NO integrity check: ~47% of single-character corruptions of a card code still decode
// into a structurally valid record carrying a DIFFERENT valid key, and the giving flow would fund an
// address no key opens. v2 appends checksum(5) = first 5 bytes of SHA-256 over the preceding 41 bytes,
// covering everything including the serial. Chosen over bech32m deliberately: 46 bytes is 62 base64url
// chars, which keeps the printed QR at the SAME version and module size as v1 by arithmetic, not by
// encoder tricks a future tool could silently drop. Odds a random corruption survives: 1 in 2^40.
export const RECORD_V1_LEN = 41, RECORD_V2_LEN = 46, CHECKSUM_LEN = 5;
export function recordChecksum(bytes41){ return sha256(bytes41).slice(0, CHECKSUM_LEN); }
export function buildRecord(P1bytes, serial){   // new records are v2; v1 exists only on already-printed cards
  const r = new Uint8Array(RECORD_V2_LEN);
  r[0]=0x02; r[1]=NETWORK; r[2]=SCRIPT; r[3]=KDF;
  r.set(P1bytes, 4);
  r.set(u32be(serial>>>0), 37);
  r.set(recordChecksum(r.slice(0, RECORD_V1_LEN)), RECORD_V1_LEN);
  return r;
}
// Parse + structurally validate a card record (open standard — cards carry NO issuer signature).
// PERMANENCE RULE: v1 support must never be removed. 300 v1 cards were printed in 2026 and remain valid
// bearer instruments for as long as one of them exists. test-record-v2.mjs pins a frozen v1 record so a
// tree that cannot read v1 fails its gate.
export function parseCard(uri){
  uri = (uri||'').trim();
  if(!uri.startsWith('bitcard:')) throw new Error('not a bitcard: card');
  const record = b64u.decode(uri.slice(8));
  if(record.length !== RECORD_V1_LEN && record.length !== RECORD_V2_LEN) throw new Error('bad card length');
  const version = record[0];
  if(version !== 0x01 && version !== 0x02) throw new Error('unsupported version');
  if(version === 0x01 && record.length !== RECORD_V1_LEN) throw new Error('bad card length');
  if(version === 0x02 && record.length !== RECORD_V2_LEN) throw new Error('bad card length');
  if(version === 0x02){
    // checksum FIRST: on a corrupted code every later field is noise, and a clean reject here is the
    // entire reason v2 exists. Constant-time comparison is unnecessary; nothing here is secret.
    const want = recordChecksum(record.slice(0, RECORD_V1_LEN));
    for(let i = 0; i < CHECKSUM_LEN; i++){
      if(record[RECORD_V1_LEN + i] !== want[i]) throw new Error('card code fails its checksum (one character is probably mistyped)');
    }
  }
  if(record[1]!==NETWORK) throw new Error('network mismatch');
  if(record[2]!==SCRIPT) throw new Error('unsupported script type');
  if(record[3]!==KDF) throw new Error('unsupported kdf');
  const P1 = record.slice(4,37);
  const P1hex = hexlib.encode(P1);
  pointFromPub(P1hex); // reject malformed cards (P1 not a valid curve point) before any key material
  const serial = ((record[37]<<24)|(record[38]<<16)|(record[39]<<8)|record[40])>>>0;
  return { P1hex, serial, version };
}
export const parseAndVerifyCard = parseCard; // back-compat alias for existing callers

// ---- known-batch check: the missing checksum, retrofitted without reprinting ----
// A v1 record carries no checksum. Roughly 40% of single-character corruptions of a card code still decode
// to a structurally valid record holding a DIFFERENT valid public key, and the giving flow would then show
// a perfectly normal deposit address that no key on earth opens. QR scanning is not the risk (Reed-Solomon
// either decodes correctly or fails); hand-typing and OCR are.
// We cannot add a checksum to printed cards, but we do know the real public key for every card we made.
// Returns 'ok' | 'mismatch' | 'unknown'. 'unknown' is NOT a failure: cards outside our range must keep
// working, or this stops being an open standard and starts being a permission slip from us.
// version matters: the table exists ONLY because a v1 record cannot check itself. A v2 record carries its
// own checksum, so applying the v1 table to it adds nothing and creates a way to brick a legitimate card:
// mint v2 cards over a serial range the table already covers and every app would call them counterfeit.
// Callers pass the record version and must enforce a mismatch only for versions that lack a checksum.
export function knownCardStatus(P1hex, serial, version){
  const B = KNOWN_BATCH;
  if(version !== undefined && version !== 1) return 'unknown';   // self-checking formats do not need the table
  if(!B || !Array.isArray(B.segments) || !Number.isInteger(serial)) return 'unknown';
  // serial ranges are allocated per print job and leave gaps, so the table is a list of contiguous
  // segments rather than one run; a serial in none of them is a card we did not make, not an error
  const seg = B.segments.find(s => serial >= s.start && serial <= s.end);
  if(!seg) return 'unknown';
  let blob;
  try{ blob = b64std.decode(seg.hashes); }catch(e){ return 'unknown'; }
  const off = (serial - seg.start) * B.trunc;
  if(off + B.trunc > blob.length) return 'unknown';
  let want;
  try{ want = sha256(hexlib.decode(P1hex)).slice(0, B.trunc); }catch(e){ return 'mismatch'; }
  for(let i = 0; i < B.trunc; i++) if(blob[off + i] !== want[i]) return 'mismatch';
  return 'ok';
}

// ---- FROZEN VECTOR: the shipped build's anchor to the PUBLISHED standard ----
// A self-test built from random input only proves the build agrees with itself. If any step of
// mnemonic -> seed -> scalar -> address ever drifted (a dependency bump, a tampered transitive package,
// a bundler transform), setup would derive a wrong address, the mandatory re-type check would re-derive
// the SAME wrong address and pass, and a random self-test would print PASS. Every gate in the product
// would confirm the broken build, and the words plus the open standard would not find the money.
// That is the Coldcard shape, so the shipped apps must verify against fixed, published values.
export const FROZEN_VECTOR = {
  part1: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
  part2: 'legal winner thank year wave sausage worth useful legal winner thank yellow',
  addressMainnet: 'bc1q6h6zqgr7pzgf4e2j86f2v4m60r5p0wqrvtkvyg',
  addressTestnet: 'tb1q6h6zqgr7pzgf4e2j86f2v4m60r5p0wqrxddllm',
  wifMainnet: 'L2GNgkXGSNjb1fTyt9WSbwHX8s3LwRRYNExo8AoBAg2yTDJMnXBF'
};
// SECOND anchor, and the reason there are two: in the vector above d1+d2 is LESS than the curve order, so
// it never exercises the "mod n" reduction. Both halves are near-uniform in [0,n), so d1+d2 >= n for close
// to HALF of all real cards. A reduction that drifted (a wrong constant, an implementation that forgot to
// reduce, a library changing how it accepts an out-of-range scalar) would break about half of a batch while
// the first vector stayed green. This pair wraps, so the reduction is pinned too.
// Both use published BIP39 test mnemonics, so an outside reviewer can reproduce them without trusting us.
export const FROZEN_VECTOR_WRAP = {
  part1: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
  part2: 'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong',
  addressMainnet: 'bc1qlpcjezx3dlyyywdq0g6qp6r0gjkk4rcekk0z25',
  addressTestnet: 'tb1qlpcjezx3dlyyywdq0g6qp6r0gjkk4rceus5338',
  wifMainnet: 'KwYfzgnFwKzL4eJAzhnph2BwkCNHNDmvznGLpBiKQqyqDhChtoQa'
};
// Costs four PBKDF2 runs, which the old random self-test already partly paid for. Returns the detail so
// the caller can refuse to operate rather than merely reporting a failure.
export function verifyFrozenVector(){
  const main = NET.hrp === 'bc';
  const expected = main ? FROZEN_VECTOR.addressMainnet : FROZEN_VECTOR.addressTestnet;
  try{
    const out = combine(halfScalar(FROZEN_VECTOR.part1), halfScalar(FROZEN_VECTOR.part2));
    const wifOK = !main || toWIF(out.d) === FROZEN_VECTOR.wifMainnet;
    const wExp = main ? FROZEN_VECTOR_WRAP.addressMainnet : FROZEN_VECTOR_WRAP.addressTestnet;
    const wOut = combine(halfScalar(FROZEN_VECTOR_WRAP.part1), halfScalar(FROZEN_VECTOR_WRAP.part2));
    const wrapOK = wOut.address === wExp && (!main || toWIF(wOut.d) === FROZEN_VECTOR_WRAP.wifMainnet);
    return { ok: out.address === expected && wifOK && wrapOK, expected, got: out.address, wifOK,
             wrapOK, wrapExpected: wExp, wrapGot: wOut.address };
  }catch(e){ return { ok:false, expected, got:'error: '+e.message, wifOK:false, wrapOK:false }; }
}

// Normalize a typed or pasted word list. The invisible characters below are inserted routinely by chat
// apps, PDFs and web pages, and they are the worst possible failure: the rejected word LOOKS correct on
// screen, so the customer retypes it identically forever. Stripping them changes no security property,
// because the BIP39 checksum still has to pass afterwards.
export function normWords(s){
  return String(s == null ? '' : s)
    .replace(/[\u200B-\u200D\uFEFF\u00AD]/g, '')   // zero-width space/joiners, BOM, soft hyphen
    .replace(/[,;]+/g, ' ')                        // comma or semicolon separated lists
    .trim().toLowerCase().replace(/\s+/g, ' ');
}

// Accept whatever a person can plausibly paste. Real inputs seen in the wild include the whole link from a
// camera app, a link forwarded in a message with words around it, a link whose "#" arrived percent-encoded,
// the bare record, a "bitcard:" code, and any of those wrapped in spaces, newlines, or trailing punctuation.
// Strategy: take everything after the LAST fragment marker, then keep only the leading run of base64url
// characters. That discards trailing prose, punctuation and whitespace without ever rewriting what the
// person typed (the input box is untouched; this only normalizes at parse time).
export function normCardInput(v){
  v = String(v == null ? '' : v).trim();
  // Find EVERY valid card record anywhere in the input, not just the last one. A person can easily paste a
  // message containing two different card links; silently choosing one would let a buyer write their words on
  // the card in their hand while funding an address derived from the OTHER card's key half, which is
  // unrecoverable. Ambiguity must therefore fail loudly instead of picking a winner.
  const found = [];
  for(const run of (v.match(/[A-Za-z0-9_-]+/g) || [])){
    const rec = run.replace(/^bitcard:/i, '');
    try{ parseCard('bitcard:' + rec); if(found.indexOf(rec) < 0) found.push(rec); }catch(e){}
  }
  if(found.length > 1) throw new Error('multiple cards pasted');
  if(found.length === 1) return 'bitcard:' + found[0];
  // Nothing valid yet (partial typing, junk, a bare URL): fall back to the fragment so the status line can
  // still tell the difference between "not finished pasting" and "this is not a card code".
  const hh = v.lastIndexOf('#');
  const pp = v.toLowerCase().lastIndexOf('%23');
  if(hh >= 0 || pp >= 0){
    v = (hh > pp) ? v.slice(hh + 1) : v.slice(pp + 3);
  }
  v = v.trim().replace(/^bitcard:/i, '').trim();
  const m = v.match(/^[A-Za-z0-9_-]+/);
  return m ? 'bitcard:' + m[0] : '';
}

// ---- guarded key generation ----
// Every set of words in the product comes from here, so the check cannot be present at one call site and
// missing at another. A CSPRNG normally either works or throws, but a generator stuck at a constant returns
// SUCCESSFULLY with dead bytes: 16 zero bytes produce 'abandon abandon ... about', a phrase printed in every
// BIP39 tutorial. Accepting that is silent and permanent. If it happened on a buyer's device the two-half
// scheme would quietly collapse to one half, and because the card's public key is printed on the card,
// anyone could compute the funding address and watch for it. Nothing visible would be wrong at the time.
//
// Refuse loudly rather than retry: a stuck generator would make a retry loop spin forever, and a caller
// that swallows this error is a bug we want to see immediately, not a silent weak key.
// A healthy draw trips neither check: 16 identical bytes is 2^-120, and two equal draws is 2^-128.
export function newMnemonic(){
  const a = bip39.generateMnemonic(wordlist, 128);
  const b = bip39.generateMnemonic(wordlist, 128);
  if(a === b) throw new Error('this device returned the same random value twice, so it cannot make safe words [RNG-01]');
  for(const m of [a, b]){
    const e = bip39.mnemonicToEntropy(m, wordlist);
    let constant = true;
    for(let i = 1; i < e.length; i++){ if(e[i] !== e[0]){ constant = false; break; } }
    if(constant) throw new Error('this device returned a constant random value, so it cannot make safe words [RNG-01]');
  }
  return a;   // b is discarded: it exists only to prove the generator moves
}

// ---- key scheme (spec §3) ----
export function halfScalar(mnemonic){
  if(!bip39.validateMnemonic(mnemonic.trim().toLowerCase(), wordlist)) throw new Error('bad BIP39 mnemonic/checksum');
  const seed = bip39.mnemonicToSeedSync(mnemonic.trim().toLowerCase(), '');
  const I = hmac(sha512, utf8ToBytes('Bitcoin seed'), seed);
  const k = bytesToBig(I.slice(0,32));
  if(k === 0n || k >= n) throw new Error('invalid master scalar (reject per §3.4)');
  return k;
}
export function pubOfScalar(k){ return secp.getPublicKey(bigToBytes32(k), true); }
export function pointFromPub(pubHex){ const P = secp.ProjectivePoint.fromHex(pubHex); P.assertValidity(); return P; }
export function addrFromPubBytes(pub){ return btc.p2wpkh(pub, BTCNET).address; }
// WIF for the combined key, so an OFFLINE tool can hand it to a standard wallet's Sweep feature.
// Compressed key; network (version byte) comes from BTCNET so testnet/mainnet are both correct.
export function toWIF(d){
  const key = bigToBytes32(d);
  const payload = new Uint8Array(34);
  payload[0] = (BTCNET.wif !== undefined ? BTCNET.wif : 0x80); payload.set(key, 1); payload[33] = 0x01;
  const chk = sha256(sha256(payload)).slice(0, 4);
  const full = new Uint8Array(38); full.set(payload, 0); full.set(chk, 34);
  return base58.encode(full);
}
export function setupAddress(p1pubHex, d2){
  const P1 = pointFromPub(p1pubHex);
  const P = P1.add(secp.ProjectivePoint.fromPrivateKey(bigToBytes32(d2)));
  if(P.equals(secp.ProjectivePoint.ZERO)) throw new Error('P is infinity (reject §3.4)');
  return addrFromPubBytes(P.toRawBytes(true));
}
export function combine(d1, d2){
  const d = (d1 + d2) % n;
  if(d === 0n) throw new Error('combined key is zero (reject §3.4)');
  const pub = pubOfScalar(d);
  return { d, pub, address: addrFromPubBytes(pub) };
}
export function showBuildHash(){
  try{
    const el = document.getElementById('appbundle');
    if(el && el.textContent){
      const h = hexlib.encode(sha256(utf8ToBytes(el.textContent)));
      $('buildhash').textContent = 'running build hash (self-computed): '+h;
    } else { $('buildhash').textContent = 'running build hash: (dev build — not bundled)'; }
  }catch(e){ $('buildhash').textContent = 'build hash error: '+e.message; }
}
