// Regenerate the PUBLISHED spec vectors. Every field is computed, never hand-typed: these are the values
// an outside implementer checks their code against, so a transcription slip here would send a correct
// third-party implementation chasing a bug that does not exist, or bless a broken one.
//
// Vector 3 is the important addition. In vectors 1 and 2 d1+d2 is less than the curve order, so nothing in
// this file ever exercised the "mod n" reduction, even though roughly half of all real cards need it.
//
// Run: node gen-test-vectors.mjs   (writes ../spec/bitcard-test-vectors.json)
import { halfScalar, toWIF, buildRecord, parseAndVerifyCard, pubOfScalar, b64u } from './core.js';
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
    note: 'Cards carry NO issuer signature (open, permissionless standard). The QR payload is base64url(record) with nothing appended. Two record versions exist. v1(41) = version=1(1) | network(1) | scripttype(1) | kdf(1) | P1(33, compressed) | serial(4, uint32 BE). v2(46) = the same 41 bytes with version=2, followed by checksum(5) = the first 5 bytes of SHA-256 over those 41 bytes. v1 has NO integrity check: a single-character substitution can decode to a structurally valid different key and serial. v2 closes that accidental-corruption path: a conformant parser MUST verify the checksum and reject on mismatch. Claim/recovery parsers retain v1 compatibility while issued v1 bearer instruments exist; official Setup/Give refuses unknown or mismatched v1 records.',
    recordV1Testnet: {
      note: 'Historical labelled testnet example. A mainnet-only parser is expected to reject its network byte.',
      recordHex: '0101010103d902f35f560e0470c63313c7369168d9d7df2d49bf295fd9fb7cb109ccee049400000001',
      expectInMainnetBuild: 'reject-network-mismatch'
    },
    recordV1Mainnet: (() => {
      // Reserved, never-minted serial. This gives implementers a v1 example that a mainnet parser must accept.
      const SERIAL = 4294967122;
      const P1 = pubOfScalar(halfScalar(M.abandon));
      const rec = buildRecord(P1, SERIAL).slice(0, 41);
      rec[0] = 0x01;
      const b = b64u.encode(rec);
      const chk = parseAndVerifyCard('bitcard:' + b);
      if (chk.serial !== SERIAL || chk.version !== 1) throw new Error('v1 mainnet vector does not round-trip');
      return {
        note: 'Same P1 as vector 1 part1, mainnet network byte, and reserved never-minted serial 4294967122.',
        recordHex: hex.encode(rec),
        cardURI: 'bitcard:' + b,
        expect: 'accept'
      };
    })(),
    recordV2: (() => {
      // serial from the RESERVED range (>= 4294000000, never minted): a published example must not
      // collide with a real card, or pasting it into the live app trips the known-batch check
      const SERIAL = 4294967123;
      const P1 = pubOfScalar(halfScalar(M.abandon));
      const rec = buildRecord(P1, SERIAL);
      const b = b64u.encode(rec);
      const chk = parseAndVerifyCard('bitcard:' + b);   // generator refuses to publish a vector its own parser rejects
      if (chk.serial !== SERIAL || chk.version !== 2) throw new Error('v2 vector does not round-trip');
      return {
        note: 'Same P1 as vector 1 part1 (a published BIP39 test mnemonic), serial 4294967123 (from the reserved never-minted range), so every byte is reproducible.',
        recordHex: hex.encode(rec),
        cardURI: 'bitcard:' + b,
        checksumHex: hex.encode(rec.slice(41)),
        corruptionVectors: [
          { note: 'serial byte flipped: checksum MUST reject (the checksum covers the serial)',
            cardURI: 'bitcard:' + b64u.encode((() => { const r = Uint8Array.from(rec); r[40] ^= 1; return r; })()), expect: 'reject' },
          { note: 'one P1 byte flipped: checksum MUST reject',
            cardURI: 'bitcard:' + b64u.encode((() => { const r = Uint8Array.from(rec); r[10] ^= 1; return r; })()), expect: 'reject' },
          { note: 'compressed-point prefix flipped 03 to 02 (a valid curve point, the dangerous v1 case): checksum MUST reject',
            cardURI: 'bitcard:' + b64u.encode((() => { const r = Uint8Array.from(rec); r[4] ^= 1; return r; })()), expect: 'reject' }
        ]
      };
    })(),
    encoding: "cardURI = 'bitcard:' + base64url_nopad(record). The claim app validates version/network/scripttype/kdf, the v2 checksum, and that P1 is a valid secp256k1 point; there is no signature to verify."
  },
  vectors: [
    vec(M.abandon, M.legal, 'canonical pair; d1+d2 < n so no reduction occurs'),
    vec(M.legal, M.abandon, 'vector 1 with the halves swapped; address MUST match vector 1'),
    vec(M.abandon, M.zoo,   'REDUCTION CASE: d1+d2 >= n. An implementation that omits mod n fails only here.'),
  ]
};

const path = new URL('../spec/bitcard-test-vectors.json', import.meta.url);
writeFileSync(path, JSON.stringify(out, null, 2) + '\n');
console.log('wrote ' + out.vectors.length + ' vectors');
for (const v of out.vectors) console.log('  reduced=' + String(v.reducedModN).padEnd(5) + ' ' + v.addressMainnet);
