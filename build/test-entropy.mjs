// ENTROPY AUDIT: the Coldcard failure class.
//
// Coldcard's 2021 firmware routed seed generation through a SOFTWARE RNG instead of the hardware one.
// The keys looked perfect, nothing failed, no test caught it, and five years later ~$89M was drained
// from ~4,585 dormant addresses. A weak generator is silent, permanent and unverifiable after the fact.
//
// This audit answers one question: is every byte of Bitcard key material sourced from a platform CSPRNG,
// with no custom, seeded, or fallback path anywhere?
//
// Run: node test-entropy.mjs
import fs from 'node:fs';
import { randomBytes } from '@noble/hashes/utils';
import * as bip39 from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';

let pass = 0, fail = 0;
const ok = (n, c, d) => { c ? pass++ : (fail++, console.log('FAIL: ' + n + (d !== undefined ? '\n      ' + d : ''))); };

// ---------- 1. No weak or custom randomness anywhere in our own source ----------
// The Coldcard bug was a code path that BYPASSED the good source. Any of these in our tree is a red flag.
const OURS = ['core.js','net.js','config.js','endpoints.js','app-claim.js','app-offline.js','app-maker.js','app-qc.js','mint-pilot-csv.mjs','merge-pilot-csv.mjs','assemble.mjs'];
const BANNED = [
  ['Math.random',            'Math.random is not cryptographic'],
  ['Date.now() %',           'time-seeded randomness'],
  ['new Date().getTime() %', 'time-seeded randomness'],
  ['seed(',                  'a seeded generator'],
  ['mulberry',               'a userland PRNG'],
  ['xorshift',               'a userland PRNG'],
  ['lcg',                    'a linear congruential generator'],
];
for (const f of OURS) {
  let s; try { s = fs.readFileSync(new URL(f, import.meta.url), 'utf8'); } catch (e) { continue; }
  for (const [needle, why] of BANNED) ok(f + ': no ' + why, !s.includes(needle));
}

// ---------- 2. Key material comes from exactly one place, and it is the platform CSPRNG ----------
// Our apps never call a random function directly; they call bip39.generateMnemonic, which draws from
// @noble/hashes randomBytes, which is crypto.getRandomValues (browser) / node:crypto (server).
for (const f of ['app-claim.js', 'app-offline.js', 'mint-pilot-csv.mjs']) {
  let s; try { s = fs.readFileSync(new URL(f, import.meta.url), 'utf8'); } catch (e) { continue; }
  const gens = (s.match(/generateMnemonic\(/g) || []).length;
  const direct = (s.match(/randomBytes\(|getRandomValues\(/g) || []).length;
  ok(f + ': key material only via generateMnemonic, no hand-rolled draws', direct === 0, direct + ' direct calls');
  if (f !== 'app-offline.js') ok(f + ': does generate keys (' + gens + ' call sites)', gens > 0);
}

// ---------- 3. The library FAILS CLOSED, verified by reading its source ----------
// This is the exact property Coldcard lacked: their firmware silently degraded to a software RNG.
// Runtime probing cannot prove this (the module captures its crypto reference at import time, so
// deleting the global afterwards changes nothing), so we assert on the shipped dependency source.
// This doubles as a SUPPLY CHAIN guard: if an update ever introduces a weak fallback, this fails.
{
  let src = null;
  try { src = fs.readFileSync(new URL('node_modules/@noble/hashes/utils.js', import.meta.url), 'utf8'); } catch (e) {}
  ok('entropy library source is readable for audit', src !== null);
  if (src) {
    const body = (src.match(/function randomBytes\([\s\S]*?\n\}/) || [''])[0];
    ok('randomBytes uses WebCrypto getRandomValues', /getRandomValues\(new Uint8Array/.test(body));
    ok('its only other path is node crypto randomBytes', /crypto\.randomBytes\(bytesLength\)/.test(body));
    ok('it THROWS when no secure source exists, never degrades', /throw new Error\('crypto\.getRandomValues must be defined'\)/.test(body));
    ok('no non-cryptographic fallback in the entropy path', !/Math\.random|Date\.now|performance\.now/.test(body), body.slice(0, 200));
    const returns = (body.match(/return /g) || []).length;
    ok('exactly two return paths, both cryptographic (got ' + returns + ')', returns === 2, body);
  }
}

// ---------- 4. Live output sanity: catastrophic failure would show here ----------
// Honest limit, stated plainly: these checks catch a BROKEN generator (constant, repeating, tiny period).
// They cannot catch a generator that is uniform but low-entropy, e.g. seeded from 32 bits. Only the code
// path audit above can rule that out, which is why sections 1 to 3 matter more than this one.
{
  const N = 300, seen = new Set(); let ones = 0, total = 0;
  const popcount = b => b.toString(2).split('1').length - 1;
  for (let i = 0; i < N; i++) {
    const m = bip39.generateMnemonic(wordlist, 128);
    seen.add(m);
    for (const b of bip39.mnemonicToEntropy(m, wordlist)) { ones += popcount(b); total += 8; }
  }
  ok(N + ' freshly generated mnemonics are all distinct', seen.size === N, seen.size + ' distinct');
  const ratio = ones / total;
  ok('bit balance plausible (0.45 to 0.55), got ' + ratio.toFixed(4), ratio > 0.45 && ratio < 0.55);
  ok('a full 128 bits of entropy per half', bip39.mnemonicToEntropy([...seen][0], wordlist).length === 16);
}

// ---------- 5. The 300 cards ALREADY MINTED: public data only, no secrets read ----------
// If the generator had failed, these keys are already compromised and the cards must not ship.
{
  const p = 'C:/Users/Cameron/bitcard-mint/bitcard-print-300-QC-manifest.json';
  let man = null;
  try { man = JSON.parse(fs.readFileSync(p, 'utf8')); } catch (e) { console.log('  (skipped: manifest not present on this machine)'); }
  if (man) {
    const keys = man.cards.map(c => c.p1Hex);
    ok('minted batch: 300 cards present', keys.length === 300, keys.length);
    ok('minted batch: every public key distinct', new Set(keys).size === keys.length);
    // any repeated 8-hex-char run across different cards would indicate a tiny-period generator
    const frag = new Map(); let collide = 0;
    keys.forEach((k, i) => { for (let j = 2; j + 8 <= k.length; j += 8) {
      const f = k.slice(j, j + 8);
      if (frag.has(f) && frag.get(f) !== i) collide++; else frag.set(f, i);
    }});
    ok('minted batch: no repeated key fragments across cards', collide === 0, collide + ' collisions');
    const nib = new Array(16).fill(0); let nt = 0;
    for (const k of keys) for (const ch of k.slice(2)) { nib[parseInt(ch, 16)]++; nt++; }
    const exp = nt / 16, chi = nib.reduce((s, o) => s + (o - exp) ** 2 / exp, 0);
    ok('minted batch: hex digits evenly distributed (chi-square ' + chi.toFixed(1) + ' < 40 for df=15)', chi < 40);
  }
}

console.log('\n' + (fail === 0 ? 'ENTROPY OK (' + pass + ' passed)' : 'ENTROPY FAILED (' + fail + ' failures)'));
process.exit(fail === 0 ? 0 : 1);
