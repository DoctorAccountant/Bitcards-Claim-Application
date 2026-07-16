// Bitcard shared core (spec v0.3). PUBLIC material only — this module contains NO maker private key.
// Imported by both the public claim app and the internal maker tool.
import { secp256k1 as secp } from '@noble/curves/secp256k1';
import { hmac } from '@noble/hashes/hmac';
import { sha512 } from '@noble/hashes/sha512';
import { sha256 } from '@noble/hashes/sha256';
import { utf8ToBytes } from '@noble/hashes/utils';
import * as bip39 from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import * as btc from '@scure/btc-signer';
import { hex as hexlib, base64urlnopad as b64u } from '@scure/base';
import { NET, ACTIVE } from './config.js';   // all network params (testnet/mainnet) come from here

export { secp, sha256, utf8ToBytes, bip39, wordlist, btc, hexlib, b64u, NET, ACTIVE };

// secp.btc network object for the active network (address encoding). Mainnet defined explicitly so we don't depend on a library export.
const BTC_MAINNET = { bech32: 'bc', pubKeyHash: 0x00, scriptHash: 0x05, wif: 0x80 };
export const BTCNET = NET.hrp === 'bc' ? BTC_MAINNET : btc.TEST_NETWORK;
export const NETWORK = NET.networkByte, SCRIPT = 0x01, KDF = 0x01; // network byte from config; P2WPKH, BIP39->BIP32-master

export const n = secp.CURVE.n;
export const $ = id => document.getElementById(id);
// textContent-only renderer: node- and user-supplied strings are never parsed as HTML (spec §10 P1 hardening).
export const log = (el, s, cls) => { const e = $(el); if(!e) return; e.textContent = ''; if(cls){ const sp = document.createElement('span'); sp.className = cls; sp.textContent = s; e.appendChild(sp); } else { e.textContent = s; } };

// ---- network helpers (claim app only; the maker tool imports none of these) ----
export const NODES = NET.nodes;
export async function fetchJSON(base, path){ const r = await fetch(base+path); if(!r.ok) throw new Error('http '+r.status); return r.json(); }
export async function getUtxos(addr){ // §7: require ALL nodes to respond AND agree on spend-critical data before signing
  const res = await Promise.allSettled(NODES.map(b=>fetchJSON(b,'/address/'+addr+'/utxo')));
  const ok = res.filter(r=>r.status==='fulfilled').map(r=>r.value);
  if(ok.length < NODES.length) throw new Error('only '+ok.length+'/'+NODES.length+' nodes responded — refusing to sign; §7 requires agreement of all nodes');
  const key = u => u.map(x=>x.txid+':'+x.vout+':'+x.value+':'+(x.status&&x.status.confirmed?1:0)).sort().join(',');
  for(let i=1;i<ok.length;i++){ if(key(ok[i])!==key(ok[0])) throw new Error('nodes disagree on UTXO set/values — refusing to sign (§7)'); }
  return { utxos: ok[0], agreed: ok.length };
}
// Fee estimate from the first responding node (NOT node-agreement — agreement is required for UTXOs, not fees). Bounded by MAX_FEERATE + 50% cap + dust refusal.
export async function feeRate(){ for(const b of NODES){ try{ const f=await fetchJSON(b,'/fee-estimates'); return Math.max(1, Math.ceil(f['2']||f['3']||f['6']||2)); }catch(e){} } return 2; }
export function estVbytes(nIn){ return Math.ceil(10.5 + nIn*68 + 31); } // P2WPKH sweep, 1 output
export const MAX_FEERATE = 100; // sat/vB sanity ceiling (§7 upper bound)
export async function broadcastTx(raw){ // §7: post to ALL nodes; succeed if any accepts; report each
  const res = await Promise.allSettled(NODES.map(async b => { const r = await fetch(b+'/tx',{method:'POST',body:raw}); const t = await r.text(); if(!r.ok) throw new Error(t); return t; }));
  const accepted = [], errs = [];
  res.forEach((r,i)=>{ const host = NODES[i].split('//')[1]; if(r.status==='fulfilled'){ accepted.push({host, txid:r.value}); } else { errs.push(host+': '+(r.reason&&r.reason.message||r.reason)); } });
  if(!accepted.length) throw new Error('all nodes rejected: '+errs.join(' | '));
  return { txid: accepted[0].txid, acceptedHosts: accepted.map(a=>a.host), errs };
}

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
