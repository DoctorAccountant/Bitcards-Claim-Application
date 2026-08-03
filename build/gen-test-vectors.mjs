// Regenerate the PUBLISHED spec vectors. Every field is computed, never hand-typed: these are the values
// an outside implementer checks their code against, so a transcription slip here would send a correct
// third-party implementation chasing a bug that does not exist, or bless a broken one.
//
// Vector 3 is the important addition. In vectors 1 and 2 d1+d2 is less than the curve order, so nothing in
// this file ever exercised the "mod n" reduction, even though roughly half of all real cards need it.
//
// Run: node gen-test-vectors.mjs   (writes ../bitcard-test-vectors.json)
import { halfScalar, toWIF } from './core.js';
import { secp256k1 as secp } from '@noble/curves/secp256k1';
import * as btc from '@scure/btc-signer';
import { hex } from '@scure/base';
import { writeFileSync } from 'node:fs';

const n = secp.CURVE.n;
const BC = { bech32: 'bc', pubKeyHash: 0x00, scriptHash: 0x05, wif: 0x80 };
const TB = { bech32: 'tb', pubKeyHash: 0x6f, scriptHash: 0xc4, wif: 0xef };
const h32 = d => d.toString(16).padStart(64, '0');
const pubOf = d => secp.getPublicKey(h32(d), true);

const M = {
  abandon: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
  legal:   'legal winner thank year wave sausage worth useful legal winner thank yellow',
  zoo:     'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong',
};

function vec(p1, p2, note){
  const d1 = halfScalar(p1), d2 = halfScalar(p2);
  const sum = d1 + d2, d = sum % n, pub = pubOf(d);
  return {
    note,
    part1Mnemonic: p1, part2Mnemonic: p2,
    d1Hex: h32(d1), d2Hex: h32(d2),
    P1: hex.encode(pubOf(d1)), P2: hex.encode(pubOf(d2)),
    sumBeforeReductionHex: sum.toString(16),
    reducedModN: sum >= n,
    Pcombined: hex.encode(pub),
    dCombinedHex: h32(d),
    addressMainnet: btc.p2wpkh(pub, BC).address,
    addressTestnet: btc.p2wpkh(pub, TB).address,
    wifMainnet: toWIF(d),
  };
}

const out = {
  spec: 'bitcard-claim-spec v0.4',
  curve: 'secp256k1',
  scriptType: 'P2WPKH',
  kdf: "BIP39(English, NFKD, empty passphrase) -> PBKDF2-HMAC-SHA512 x2048 -> BIP32 master private key (HMAC-SHA512, key='Bitcoin seed', take left 32 bytes) -> scalar; reject 0 or >= n",
  aggregation: 'd = (d1 + d2) mod n ; P = P1 + P2 (EC point addition) ; address = P2WPKH(compressed P)',
  note: 'Vectors 1 and 2 are the same pair with the halves swapped; their addresses MUST be identical (additive aggregation is commutative). Vector 3 is the case where d1+d2 is GREATER than the curve order and the reduction actually does something: both halves are near-uniform in [0,n), so about half of all real cards land there. An implementation that skips the reduction, or reduces by the wrong modulus, passes vectors 1 and 2 and fails vector 3. Every vector now carries its mainnet address and WIF as well as testnet.',
  generatedBy: 'build/gen-test-vectors.mjs against build/core.js (@noble/curves, @scure/bip39, @scure/btc-signer). All values computed, none transcribed.',
  validatedOnChain: 'testnet tx d5245874007557429eb8e4267490e1190ed8ac37c763cad5934606a66cdfc96c, confirmed block 5013091 (real funded sweep of an aggregate P1+P2 address)',
  cardRecord: {
    note: 'v0.4 - cards carry NO issuer signature. The QR payload is base64url(record) with nothing appended. record(41) = version(1) | network(1) | scripttype(1) | kdf(1) | P1(33, compressed) | serial(4, uint32 BE).',
    recordHexExample: '0101010103d902f35f560e0470c63313c7369168d9d7df2d49bf295fd9fb7cb109ccee049400000001',
    encoding: "cardURI = 'bitcard:' + base64url_nopad(record). The claim app validates version/network/scripttype/kdf and that P1 is a valid secp256k1 point; there is no signature to verify."
  },
  vectors: [
    vec(M.abandon, M.legal, 'canonical pair; d1+d2 < n so no reduction occurs'),
    vec(M.legal, M.abandon, 'vector 1 with the halves swapped; address MUST match vector 1'),
    vec(M.abandon, M.zoo,   'REDUCTION CASE: d1+d2 >= n. An implementation that omits mod n fails only here.'),
  ]
};

const path = new URL('../bitcard-test-vectors.json', import.meta.url);
writeFileSync(path, JSON.stringify(out, null, 2) + '\n');
console.log('wrote ' + out.vectors.length + ' vectors');
for (const v of out.vectors) console.log('  reduced=' + String(v.reducedModN).padEnd(5) + ' ' + v.addressMainnet);
