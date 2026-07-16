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
import { hex as hexlib, base64urlnopad as b64u, base58 } from '@scure/base';
import { NET, ACTIVE } from './config.js';        // crypto/display params (no URLs). Network layer + node URLs live in net.js.

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
export function buildRecord(P1bytes, serial){
  const r = new Uint8Array(41);
  r[0]=0x01; r[1]=NETWORK; r[2]=SCRIPT; r[3]=KDF;
  r.set(P1bytes, 4);
  r.set(u32be(serial>>>0), 37);
  return r;
}
// Parse + structurally validate a card record (open standard v0.4 — cards carry NO issuer signature).
export function parseCard(uri){
  uri = (uri||'').trim();
  if(!uri.startsWith('bitcard:')) throw new Error('not a bitcard: card');
  const record = b64u.decode(uri.slice(8));
  if(record.length !== 41) throw new Error('bad card length');
  if(record[0]!==0x01) throw new Error('unsupported version');
  if(record[1]!==NETWORK) throw new Error('network mismatch');
  if(record[2]!==SCRIPT) throw new Error('unsupported script type');
  if(record[3]!==KDF) throw new Error('unsupported kdf');
  const P1 = record.slice(4,37);
  const P1hex = hexlib.encode(P1);
  pointFromPub(P1hex); // reject malformed cards (P1 not a valid curve point) before any key material
  const serial = ((record[37]<<24)|(record[38]<<16)|(record[39]<<8)|record[40])>>>0;
  return { P1hex, serial };
}
export const parseAndVerifyCard = parseCard; // back-compat alias for existing callers

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
