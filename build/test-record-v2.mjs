// Record format v2: the checksum the printed v1 cards never had, plus the permanence pin for v1 itself.
//
// v2(46) = version=2(1) | network(1) | scripttype(1) | kdf(1) | P1(33) | serial(4 BE) |
//          checksum(5) = first 5 bytes of SHA-256 over the preceding 41 bytes.
// 46 bytes is 62 base64url chars: measured against the print pipeline (segno, ECC-L, the card's 200px
// tile), the QR stays version 5 at 37 modules, byte-identical footprint to v1. That is WHY this encoding
// won over bech32m: the size guarantee holds by arithmetic, not by encoder tricks.
//
// Run: node test-record-v2.mjs
import { buildRecord, parseAndVerifyCard, recordChecksum, pubOfScalar, halfScalar, hexlib, b64u,
         RECORD_V1_LEN, RECORD_V2_LEN } from './core.js';

let pass = 0, fail = 0;
const ok = (n, c, d) => { c ? pass++ : (fail++, console.log('FAIL: ' + n + (d !== undefined ? '\n      ' + d : ''))); };
const throws = (n, fn) => { try { fn(); ok(n, false, 'did not throw'); } catch (e) { ok(n, true); } };

// The published anchor key (BIP39 test mnemonic), so every value here is reproducible by an outsider.
const P1hex = '03d902f35f560e0470c63313c7369168d9d7df2d49bf295fd9fb7cb109ccee0494';
const P1 = pubOfScalar(halfScalar('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'));
ok('anchor key reproduces', hexlib.encode(P1) === P1hex);

// ---- PERMANENCE PIN: v1 must parse forever ----
// 300 v1 cards were printed in 2026 and remain valid bearer instruments for as long as one exists.
// This frozen record makes "someone tidied away the old format" a build failure instead of a quiet loss.
const FROZEN_V1 = 'AQABAQPZAvNfVg4EcMYzE8c2kWjZ198tSb8pX9n7fLEJzO4ElAAAAHs';
{
  const p = parseAndVerifyCard('bitcard:' + FROZEN_V1);
  ok('frozen v1 record still parses (printed cards stay claimable)', p.P1hex === P1hex && p.serial === 123 && p.version === 1,
     JSON.stringify(p));
}

// ---- frozen v2 vector (also published in bitcard-test-vectors.json) ----
// Serial 4294967123 sits in the RESERVED range (>= 4294000000, never minted, enforced by mint-pilot-csv):
// a spec vector must not collide with a real card, or pasting the published example into the live app
// trips the known-batch check and looks like a defect.
const V2_SERIAL = 4294967123;
const FROZEN_V2 = 'AgABAQPZAvNfVg4EcMYzE8c2kWjZ198tSb8pX9n7fLEJzO4ElP___1M1_M0_jA';
{
  const built = b64u.encode(buildRecord(P1, V2_SERIAL));
  ok('buildRecord reproduces the frozen v2 vector byte for byte', built === FROZEN_V2, built);
  const p = parseAndVerifyCard('bitcard:' + FROZEN_V2);
  ok('frozen v2 record parses with the right identity', p.P1hex === P1hex && p.serial === V2_SERIAL && p.version === 2);
  ok('v2 record is 46 bytes / 62 chars (QR stays version 5)', b64u.decode(FROZEN_V2).length === RECORD_V2_LEN && FROZEN_V2.length === 62);
}

// ---- THE POINT: every single-character corruption of a v2 code is harmless ----
// For v1 we measured ~47% of substitutions decoding as a valid different card. For v2 a corruption must
// either be rejected, or (if the decoder tolerates non-canonical trailing bits) decode to the IDENTICAL
// card, which funds the right address and is therefore harmless. What must never survive is a DIFFERENT
// card. No embedded batch table involved: the record now defends itself.
{
  const ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  let tested = 0, rejected = 0, sameCard = 0, differentCard = 0;
  for (let i = 0; i < FROZEN_V2.length; i++) {
    for (const ch of ALPHA) {
      if (ch === FROZEN_V2[i]) continue;
      tested++;
      let p;
      try { p = parseAndVerifyCard('bitcard:' + FROZEN_V2.slice(0, i) + ch + FROZEN_V2.slice(i + 1)); }
      catch (e) { rejected++; continue; }
      if (p.P1hex === P1hex && p.serial === V2_SERIAL) sameCard++; else differentCard++;
    }
  }
  ok('all ' + tested + ' single-char corruptions: none yields a different card ' +
     '(' + rejected + ' rejected, ' + sameCard + ' decode to the same card)', differentCard === 0,
     differentCard + ' corruptions produced a DIFFERENT valid card');
}

// ---- targeted negatives ----
{
  const rec = b64u.decode(FROZEN_V2);
  const reenc = r => 'bitcard:' + b64u.encode(r);
  // serial is covered by the checksum, so a flipped serial byte cannot mislead support or batch lookup
  const s = Uint8Array.from(rec); s[40] ^= 1;
  throws('a flipped serial byte fails the checksum', () => parseAndVerifyCard(reenc(s)));
  const c = Uint8Array.from(rec); c[45] ^= 1;
  throws('a corrupted checksum byte is rejected', () => parseAndVerifyCard(reenc(c)));
  const v = Uint8Array.from(rec); v[0] = 3;
  throws('version 3 is rejected (fail closed on formats we do not know)', () => parseAndVerifyCard(reenc(v)));
  const long46v1 = Uint8Array.from(rec); long46v1[0] = 1;
  throws('a 46-byte record claiming v1 is rejected', () => parseAndVerifyCard(reenc(long46v1)));
  throws('truncated v2 is rejected', () => parseAndVerifyCard(reenc(rec.slice(0, 45))));
  const v1as46 = new Uint8Array(46); v1as46.set(b64u.decode(FROZEN_V1));
  throws('a v1 record padded to 46 bytes is rejected', () => parseAndVerifyCard(reenc(v1as46)));
  // and the checksum function itself is pinned: first 5 bytes of a single SHA-256
  ok('checksum = SHA-256 truncated to 5 bytes (spec pin)',
     hexlib.encode(recordChecksum(rec.slice(0, RECORD_V1_LEN))) === hexlib.encode(rec.slice(41, 46)));
  // a checksum failure must be DISTINGUISHABLE from other rejections: the apps show CARD-07 ("one
  // character is mistyped, compare it with the card") rather than the generic "not a Bitcard code",
  // which is the difference between a customer fixing a typo and a customer thinking the card is broken.
  let msg = '';
  try { parseAndVerifyCard(reenc(c)); } catch (e) { msg = e.message; }
  ok('a checksum failure says so in its message (drives CARD-07)', /checksum/i.test(msg), msg);
}

// ---- the published vector must not collide with a real card ----
// Serials >= 4294000000 are reserved and mint-pilot-csv.mjs refuses them. Without that, the spec example
// would land inside a minted range and the known-batch check would flag the published vector as a forgery.
{
  const { knownCardStatus } = await import('./core.js');
  const p = parseAndVerifyCard('bitcard:' + FROZEN_V2);
  ok('the published v2 vector uses a reserved serial', p.serial >= 4294000000);
  ok('the published v2 vector is not mistaken for a minted card', knownCardStatus(p.P1hex, p.serial) === 'unknown');
}

console.log('\n' + (fail === 0 ? 'RECORD V2 OK (' + pass + ' passed)' : 'RECORD V2 FAILED (' + fail + ' failures)'));
process.exit(fail === 0 ? 0 : 1);
