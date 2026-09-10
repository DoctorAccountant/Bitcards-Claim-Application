// Frozen, independently accepted signed transaction. This prevents a signing path and a permissive test
// harness from drifting together: the expected bytes, txid, script, amount and BIP143 digest came from an
// external Bitcoin Core regtest run and are published under spec/.
import { readFileSync } from 'node:fs';
import * as btc from '@scure/btc-signer';
import { hex } from '@scure/base';
import { secp256k1 as secp } from '@noble/curves/secp256k1';

let pass = 0, fail = 0;
const ok = (n, c, d='') => c ? pass++ : (fail++, console.log('FAIL: ' + n + (d ? '\n      ' + d : '')));
const v = JSON.parse(readFileSync(new URL('../spec/bitcard-signed-transaction-vector.json', import.meta.url), 'utf8'));
const tx = btc.Transaction.fromRaw(hex.decode(v.rawSignedTransaction));

ok('frozen transaction id matches independent Bitcoin Core result', tx.id === v.txid, tx.id);
ok('frozen virtual size matches independent Bitcoin Core result', tx.vsize === v.vsize, String(tx.vsize));
ok('frozen input spends the independently recorded outpoint',
  hex.encode(tx.getInput(0).txid) === v.previousTxid && tx.getInput(0).index === v.vout);
ok('frozen output pays the independently recorded destination script',
  hex.encode(tx.getOutput(0).script) === v.destinationScript);
ok('frozen fee equals prevout minus output',
  v.previousAmountSats - Number(tx.getOutput(0).amount) === v.feeSats);

const witness = tx.getInput(0).finalScriptWitness;
ok('witness is exactly signature plus compressed public key',
  Array.isArray(witness) && witness.length === 2 && witness[1].length === 33);
if (witness && witness.length === 2) {
  const [sigWithType, pub] = witness;
  ok('witness public key hashes to the independently recorded locking script',
    hex.encode(btc.p2wpkh(pub).script) === v.previousScript);
  const scriptCode = btc.p2pkh(pub).script;
  const digest = tx.preimageWitnessV0(0, scriptCode, sigWithType.at(-1), BigInt(v.previousAmountSats));
  ok('BIP143 digest matches the independent frozen digest', hex.encode(digest) === v.BIP143Digest, hex.encode(digest));
  const sig = secp.Signature.fromDER(sigWithType.slice(0, -1));
  ok('ECDSA signature verifies against frozen prevout amount and script', secp.verify(sig, digest, pub));
  ok('signature is low-S', !sig.hasHighS());

  const wrongAmountDigest = tx.preimageWitnessV0(0, scriptCode, sigWithType.at(-1), BigInt(v.previousAmountSats + 1));
  ok('wrong prevout amount invalidates the signature', !secp.verify(sig, wrongAmountDigest, pub));
  const unrelated = new Uint8Array(hex.decode(v.previousScript)); unrelated[unrelated.length - 1] ^= 1;
  ok('wrong chain locking script cannot be accepted by self-consistency',
    hex.encode(btc.p2wpkh(pub).script) !== hex.encode(unrelated));
}

console.log('\n' + (fail === 0 ? 'SIGNED VECTOR OK (' + pass + ' passed)' : 'SIGNED VECTOR FAILED (' + fail + ' failures)'));
process.exit(fail === 0 ? 0 : 1);
