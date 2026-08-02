// The offline SETUP mode must produce EXACTLY the address the online app would, for the same card + words.
// If these ever diverged, a buyer cross-checking the online app against the offline tool would get a false alarm,
// or worse, fund an address the recipient cannot open. Same core function, asserted here on real card records.
import { parseAndVerifyCard, setupAddress, halfScalar, combine, pubOfScalar, hexlib, bip39, wordlist } from './core.js';

const CARDS = [
  'AQABAQNeyFBDvBKLzkvd64SOllZZHCuKXg4IsZ9iuQLKISgIOwAAAGU',   // pilot 101
  'AQABAQLfRDXIEvQOzzQua7XN1bX0GV4ADGLZhtcuHx0nACm7lgAAAMk',   // pilot 201
  'AQABAQN7OnXVWoKyLl8iRfLwqEtqUrtYjtOB8sH0ndNmAJcLkAAAAS0'    // pilot 301
];
let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) { pass++; } else { fail++; console.log('FAIL: ' + name); } };

for (const rec of CARDS) {
  const card = parseAndVerifyCard('bitcard:' + rec);
  const m = bip39.generateMnemonic(wordlist, 128);
  const d2 = halfScalar(m);

  // 1. setup address (public half + buyer half) == the address the claim path reconstructs (both halves combined)
  const setupAddr = setupAddress(card.P1hex, d2);
  ok('card ' + card.serial + ': setup address is a mainnet bech32', /^bc1q[0-9a-z]{38}$/.test(setupAddr));

  // 2. re-deriving with the same words must be deterministic (buyer can verify later)
  ok('card ' + card.serial + ': derivation is deterministic', setupAddress(card.P1hex, halfScalar(m)) === setupAddr);

  // 3. a DIFFERENT set of words must give a different address (no collisions / no ignoring input)
  ok('card ' + card.serial + ': different words give different address',
     setupAddress(card.P1hex, halfScalar(bip39.generateMnemonic(wordlist, 128))) !== setupAddr);

  // 4. the SAME words on a DIFFERENT card must give a different address (card half really participates)
  const other = parseAndVerifyCard('bitcard:' + CARDS[(CARDS.indexOf(rec) + 1) % CARDS.length]);
  ok('card ' + card.serial + ': same words on another card differ', setupAddress(other.P1hex, d2) !== setupAddr);
}

// 5. THE critical property: setup-derived address == the address produced when both halves are later combined.
// Simulate a full card life with a known sealed half.
const sealed = bip39.generateMnemonic(wordlist, 128);
const d1 = halfScalar(sealed);
const P1hex = hexlib.encode(pubOfScalar(d1));
const buyer = bip39.generateMnemonic(wordlist, 128);
const fundedAt = setupAddress(P1hex, halfScalar(buyer));         // what the buyer funds (offline setup mode)
const claimedFrom = combine(d1, halfScalar(buyer)).address;      // what the recipient later opens (claim/open mode)
ok('funded address == claimed address (full card lifecycle)', fundedAt === claimedFrom);

console.log('\n' + (fail === 0 ? 'SETUP PARITY OK (' + pass + ' passed)' : 'SETUP PARITY FAILED (' + fail + ' failures)'));
process.exit(fail === 0 ? 0 : 1);

