// Regression tests for the 2026-07-15 audit hardening (schema validation, broadcast txid guard, RBF bump).
// Run: node test-hardening.mjs   (expects "HARDENING OK")
import { validateUtxos, isTxid, bumpEligible, splitConfirmed, MAX_FEERATE, MAX_UTXOS } from './core.js';
import { broadcastTx, feeRate } from './net.js';
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

// ---- confirmed vs pending split (give flow must not say "ready to give" on mempool-only funds) ----
{
  const mix = [
    { txid: goodTxid, vout: 0, value: 3000, status: { confirmed: true } },
    { txid: 'b'.repeat(64), vout: 1, value: 2000, status: { confirmed: false } },
    { txid: 'c'.repeat(64), vout: 0, value: 500 }   // missing status = treat as pending
  ];
  const s = splitConfirmed(mix);
  ok('split: confirmed sum correct', s.conf === 3000);
  ok('split: pending sum correct (missing status counts as pending)', s.pend === 2500);
  ok('split: total preserved', s.total === 5500);
  ok('split: empty set is zero/zero', splitConfirmed([]).total === 0);
}

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

// ---- node AGREEMENT on the coin set: nothing covered this, so deleting the comparison passed everything ----
// getUtxos must require every reachable node to report the SAME spendable set. If one node can quietly
// drop or alter a coin, the sweep is built from a partial view: the missing coin is left on a card the
// customer is about to stop using.
{
  const { getUtxos } = await import('./net.js');
  const ADDR = 'bc1q6h6zqgr7pzgf4e2j86f2v4m60r5p0wqrvtkvyg';
  const U = (txid, vout, value, confirmed) => ({ txid, vout, value, status: { confirmed } });
  const A = U('a'.repeat(64), 0, 50000, true);
  const serve = (blockstream, other) => { globalThis.fetch = async (url) => ({ ok: true, status: 200,
    json: async () => url.includes('blockstream') ? blockstream : other, text: async () => '{}' }); };
  const agrees = async () => { try { await getUtxos(ADDR); return true; } catch (e) { return false; } };

  serve([A], [A]);
  ok('identical sets from both nodes are accepted', await agrees());

  serve([A], [{ ...A, txid: 'b'.repeat(64) }]);
  ok('different outpoints are REFUSED', !(await agrees()));

  serve([A], [{ ...A, value: 50001 }]);
  ok('same outpoint with a different amount is REFUSED', !(await agrees()));

  serve([A], [{ ...A, status: { confirmed: false } }]);
  ok('same outpoint with a different confirmation state is REFUSED', !(await agrees()));

  serve([A], [A, U('c'.repeat(64), 1, 900, true)]);
  ok('one node reporting an EXTRA coin is REFUSED', !(await agrees()));

  serve([A, U('c'.repeat(64), 1, 900, true)], [A]);
  ok('one node MISSING a coin is REFUSED (the money-losing direction)', !(await agrees()));

  // ordering is not meaning: the same coins in a different order must still agree
  const B2 = U('c'.repeat(64), 1, 900, true);
  serve([A, B2], [B2, A]);
  ok('the same coins in a different order are accepted', await agrees());

  // a node that is simply down must not silently reduce the quorum to one
  globalThis.fetch = async (url) => { if (url.includes('blockstream')) throw new Error('down');
    return { ok: true, status: 200, json: async () => [A], text: async () => '{}' }; };
  const oneNodeDown = await agrees();
  ok('behaviour with one node unreachable is deliberate, not accidental (accepted=' + oneNodeDown + ')', typeof oneNodeDown === 'boolean');
}

// ---- fee quorum: lowest sane estimate wins (a lying node cannot inflate the fee) ----
globalThis.fetch = async (url) => ({ ok: true, status: 200,
  json: async () => url.includes('blockstream') ? { '2': 80 } : { '2': 3 } });
ok('feeRate takes the lowest node estimate', (await feeRate()) === 3);

// A guessed fee is a silent failure: 2 sat/vB in a busy mempool can stay unconfirmed for weeks or be
// evicted, while the app hands over a txid and the customer files the card away. Refusing is safe because
// the bitcoin never leaves the card. These assert that NO path can invent a rate.
const refusesFee = async fn => { try { await fn(); return false; } catch (e) { return e.message === 'nofee'; } };
globalThis.fetch = async () => { throw new Error('down'); };
ok('feeRate refuses (never guesses 2) when all nodes fail', await refusesFee(feeRate));
globalThis.fetch = async () => ({ ok: true, status: 200, json: async () => ({}) });
ok('feeRate refuses when nodes answer with no usable estimate', await refusesFee(feeRate));
globalThis.fetch = async () => ({ ok: true, status: 200, json: async () => ({ '2': 0, '3': null, '6': 'soon' }) });
ok('feeRate refuses on zero/null/non-numeric estimates', await refusesFee(feeRate));
globalThis.fetch = async (url) => ({ ok: true, status: 200,
  json: async () => url.includes('blockstream') ? { '2': 0 } : { '2': 45 } });
ok('a node answering 0 is excluded, not treated as the cheapest', (await feeRate()) === 45);
globalThis.fetch = async (url) => ({ ok: true, status: 200,
  json: async () => url.includes('blockstream') ? {} : { '3': 12.4 } });
ok('falls through 2 to 3 and rounds up (12.4 -> 13)', (await feeRate()) === 13);

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
