// Node self-check of core.js crypto (no DOM needed). v0.4: cards carry no signature.
import { parseAndVerifyCard, buildRecord, halfScalar, combine, setupAddress, pubOfScalar, hexlib, b64u, NET } from './core.js';

// same witness program on both networks; only the hrp/checksum differ
const EXPECT_ADDR = NET.hrp === 'bc'
  ? 'bc1q6h6zqgr7pzgf4e2j86f2v4m60r5p0wqrvtkvyg'
  : 'tb1q6h6zqgr7pzgf4e2j86f2v4m60r5p0wqrxddllm';
console.log('active network:', NET.label);
const A = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const B = 'legal winner thank year wave sausage worth useful legal winner thank yellow';
const d1 = halfScalar(A), d2 = halfScalar(B), c = combine(d1, d2);

let pass = true;
const addrOk = c.address === EXPECT_ADDR;
const commut = combine(d2, d1).address === EXPECT_ADDR;
const aggOk = setupAddress(hexlib.encode(pubOfScalar(d1)), d2) === c.address;
console.log('vector address matches:', addrOk, '| commutative:', commut, '| setup==claim addr:', aggOk);
pass = pass && addrOk && commut && aggOk;

// card record round-trip (v0.4 — no signature; the 41-byte record IS the payload)
const P1 = pubOfScalar(d1);
const uri = 'bitcard:' + b64u.encode(buildRecord(P1, 7001));
const v = parseAndVerifyCard(uri);
const parseOk = v.P1hex === hexlib.encode(P1) && v.serial === 7001;
console.log('card record round-trips through parser + P1/serial match:', parseOk);
pass = pass && parseOk;

let neg = false;   // malformed (truncated) card must be rejected
try { parseAndVerifyCard(uri.slice(0, uri.length - 4)); } catch (e) { neg = /length|bitcard|version|curve|point|record/i.test(e.message); }
console.log('malformed card rejected:', neg);
pass = pass && neg;

console.log(pass ? '\nCORE OK' : '\nCORE FAIL');
process.exit(pass ? 0 : 1);
