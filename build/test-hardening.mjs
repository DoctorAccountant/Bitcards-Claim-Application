// Regression tests for the 2026-07-15 audit hardening (schema validation, broadcast txid guard, RBF bump).
// Run: node test-hardening.mjs   (expects "HARDENING OK")
import { validateUtxos, isTxid, broadcastTx, feeRate, bumpEligible, MAX_FEERATE, MAX_UTXOS } from './core.js';
import * as btc from '@scure/btc-signer';
import { secp256k1 as secp } from '@noble/curves/secp256k1';
import { hex as hexlib } from '@scure/base';

let pass = 0, fail = 0;
function ok(name, cond){ if(cond){ pass++; } else { fail++; console.log('  FAIL: ' + name); } }
function throws(name, fn){ try{ fn(); ok(name, false); }catch(e){ ok(name, true); } }
async function athrows(name, fn){ try{ await fn(); ok(name, false); }catch(e){ ok(name, true); } }

const goodTxid = 'a'.repeat(64);
const u = { txid: goodTxid, vout: 0, value: 5000, status: { confirmed: true } };

// ---- Esplora schema validation (malformed / hostile node JSON) ----
ok('valid utxo array passes', Array.isArray(validateUtxos([u])));
throws('non-array rejected', () => validateUtxos({}));
throws('bad txid rejected', () => validateUtxos([{ ...u, txid: 'xyz' }]));
throws('negative vout rejected', () => validateUtxos([{ ...u, vout: -1 }]));
throws('float vout rejected', () => validateUtxos([{ ...u, vout: 1.5 }]));
throws('negative value rejected', () => validateUtxos([{ ...u, value: -1 }]));
throws('unsafe value rejected', () => validateUtxos([{ ...u, value: Number.MAX_SAFE_INTEGER + 2 }]));
throws('duplicate outpoint rejected', () => validateUtxos([u, { ...u }]));
throws('too many inputs rejected', () => validateUtxos(Array.from({ length: MAX_UTXOS + 1 }, (_, i) => ({ txid: i.toString(16).padStart(64, '0'), vout: 0, value: 1 }))));

// ---- isTxid ----
ok('isTxid accepts 64-hex', isTxid(goodTxid));
ok('isTxid rejects NOT_A_TXID', !isTxid('NOT_A_TXID'));
ok('isTxid rejects short hex', !isTxid('abcd'));

// ---- broadcastTx: honest nodes echoing our txid ----
globalThis.fetch = async (url, opts) => (opts && opts.method === 'POST')
  ? { ok: true, status: 200, text: async () => goodTxid }
  : { ok: true, status: 200, text: async () => '{}' };
{
  const r = await broadcastTx('00', goodTxid);
  ok('broadcast returns our txid', r.txid === goodTxid);
  ok('both-nodes-accepted counts as independent', r.independent === true);
}

// ---- audit round 3 "lying acceptor": one node accepts with the CORRECT txid and 200s its own status endpoint,
// the other node rejects the broadcast AND does not see the tx -> must NOT be treated as independently confirmed ----
globalThis.fetch = async (url, opts) => {
  const lying = url.includes('blockstream');
  if (opts && opts.method === 'POST') return lying
    ? { ok: true, status: 200, text: async () => goodTxid }          // correct echo — passes the txid check
    : { ok: false, status: 400, text: async () => 'rejected' };
  return lying
    ? { ok: true, status: 200, text: async () => '{"confirmed":false}' }  // vouches for itself
    : { ok: false, status: 404, text: async () => '' };                    // honest node never sees it
};
{
  const r = await broadcastTx('00', goodTxid);   // includes the internal 4s propagation retry
  ok('lying acceptor cannot vouch for itself', r.independent === false);
  ok('accepted host recorded', r.acceptedHosts.length === 1);
}

// ---- same acceptor, but the OTHER host later observes the tx -> independent ----
globalThis.fetch = async (url, opts) => {
  const acceptor = url.includes('blockstream');
  if (opts && opts.method === 'POST') return acceptor
    ? { ok: true, status: 200, text: async () => goodTxid }
    : { ok: false, status: 400, text: async () => 'rejected' };
  return { ok: true, status: 200, text: async () => '{"confirmed":false}' };  // both hosts see it in the mempool
};
{
  const r = await broadcastTx('00', goodTxid);
  ok('non-accepting host observation counts as independent', r.independent === true);
}

// ---- fee quorum: lowest sane estimate wins (a lying node cannot inflate the fee) ----
globalThis.fetch = async (url) => ({ ok: true, status: 200,
  json: async () => url.includes('blockstream') ? { '2': 80 } : { '2': 3 } });
ok('feeRate takes the lowest node estimate', (await feeRate()) === 3);
globalThis.fetch = async () => { throw new Error('down'); };
ok('feeRate falls back to 2 when all nodes fail', (await feeRate()) === 2);

// ---- audit round 2 "lying broadcaster": one returns garbage 200, the other rejects -> MUST NOT report success ----
globalThis.fetch = async (url, opts) => {
  if (opts && opts.method === 'POST') return url.includes('blockstream')
    ? { ok: true, status: 200, text: async () => 'NOT_A_TXID' }
    : { ok: false, status: 500, text: async () => 'rejected' };
  return { ok: false, status: 404, text: async () => '' };
};
await athrows('lying broadcaster does NOT yield false success', () => broadcastTx('00', goodTxid));

// ---- node returns a valid-but-different txid than the one we signed -> rejected ----
globalThis.fetch = async (url, opts) => (opts && opts.method === 'POST')
  ? { ok: true, status: 200, text: async () => 'b'.repeat(64) }
  : { ok: true, status: 200, text: async () => '{}' };
await athrows('mismatched txid rejected', () => broadcastTx('00', goodTxid));

// keep the internal propagation retry fast in tests
const realSetTimeout = globalThis.setTimeout;
globalThis.setTimeout = (fn, ms) => realSetTimeout(fn, Math.min(ms || 0, 50));

// ---- sweep fee from actual vsize + RBF bump (mirrors buildSweep's two-pass approach) ----
const NETB = { bech32: 'bc', pubKeyHash: 0, scriptHash: 5, wif: 128 };
const priv = hexlib.decode('968eaeb422670fce07c620c22d7d41204ef45a104cb8e4a7e64e41791ad135b5');
const pub = secp.getPublicKey(priv, true), pay = btc.p2wpkh(pub, NETB);
const inputs = [{ txid: '11'.repeat(32), vout: 0, value: 100000 }];
function buildAt(rate){
  const total = inputs.reduce((s, x) => s + x.value, 0);
  const sign = feeSats => {
    const tx = new btc.Transaction();
    for (const x of inputs) tx.addInput({ txid: x.txid, index: x.vout, sequence: 0xfffffffd, witnessUtxo: { script: pay.script, amount: BigInt(x.value) } });
    tx.addOutputAddress(pay.address, BigInt(total - feeSats), NETB);
    tx.sign(priv); tx.finalize(); return tx;
  };
  let tx = sign(Math.max(200, Math.ceil((10.5 + 68 + 31) * rate)));
  const fee = Math.max(200, Math.ceil(tx.vsize * rate));
  tx = sign(fee);
  return { fee, vsize: tx.vsize, txid: tx.id };
}
const lo = buildAt(2), hi = buildAt(Math.ceil(2 * 1.5) + 1);
ok('sweep fee derived from actual vsize', lo.fee === Math.max(200, Math.ceil(lo.vsize * 2)));
ok('RBF bump raises the fee strictly', hi.fee > lo.fee);
ok('bump produces a replacement (different txid)', hi.txid !== lo.txid);

// ---- no-op-bump guards: the SAME bumpEligible the UI runs (audit round 4) ----
ok('bump refused when already at the fee cap', bumpEligible(MAX_FEERATE, null, null).ok === false);
ok('bump refused above the fee cap', bumpEligible(MAX_FEERATE + 50, null, null).ok === false);
ok('bump refused when rebuilt txid is identical', bumpEligible(2, goodTxid, goodTxid).ok === false);
ok('identical-txid check is case-insensitive', bumpEligible(2, goodTxid.toUpperCase(), goodTxid).ok === false);
ok('bump allowed below cap before rebuild', bumpEligible(MAX_FEERATE - 1, null, null).ok === true);
ok('bump allowed when fee can rise and txid differs', bumpEligible(2, 'b'.repeat(64), goodTxid).ok === true);

console.log('\n' + (fail ? ('HARDENING FAIL (' + fail + ' failed, ' + pass + ' passed)') : ('HARDENING OK (' + pass + ' passed)')));
process.exit(fail ? 1 : 0);
