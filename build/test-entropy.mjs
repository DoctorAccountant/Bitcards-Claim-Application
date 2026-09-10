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
let batchMode = 'not reached';
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

// ---------- 2. Key material comes from exactly one place, and that place is guarded ----------
// Every set of words must come from core's newMnemonic(), which draws from bip39.generateMnemonic (and so
// from crypto.getRandomValues / node:crypto) AND rejects a generator stuck at a constant. A call site that
// reaches generateMnemonic directly would skip that guard, so calling it outside core.js is a failure:
// this is the check that stops the stuck-RNG defense from being present in one place and missing in another.
for (const f of ['app-claim.js', 'app-offline.js', 'mint-pilot-csv.mjs']) {
  let s; try { s = fs.readFileSync(new URL(f, import.meta.url), 'utf8'); } catch (e) { continue; }
  const guarded = (s.match(/newMnemonic\(/g) || []).length;
  const raw = (s.match(/bip39\.generateMnemonic\(|[^w]generateMnemonic\(/g) || []).length;
  const direct = (s.match(/randomBytes\(|getRandomValues\(/g) || []).length;
  ok(f + ': no hand-rolled entropy draws', direct === 0, direct + ' direct calls');
  ok(f + ': never calls generateMnemonic directly (that would skip the stuck-generator guard)', raw === 0, raw + ' raw call(s)');
  ok(f + ': generates keys through the guard (' + guarded + ' call sites)', guarded > 0);
}
{
  const maker = fs.readFileSync(new URL('app-maker.js', import.meta.url), 'utf8');
  ok('retired browser maker has no raw mnemonic generator', !/generateMnemonic\(|newMnemonic\(/.test(maker));
  ok('retired browser maker disables card creation in code', /button\.disabled\s*=\s*true/.test(maker) && /Browser minting retired/.test(maker));
}
// and core.js must be the only file that reaches the raw generator
{
  const core = fs.readFileSync(new URL('core.js', import.meta.url), 'utf8');
  const inCore = (core.match(/generateMnemonic\(/g) || []).length;
  ok('core.js holds the only raw generator calls (' + inCore + ')', inCore > 0);
  ok('core.js exports the guarded generator', /export function newMnemonic\(/.test(core));
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

// ---------- 3b. A generator stuck at a constant returns SUCCESSFULLY with dead bytes ----------
// The library throws when no secure source exists, which is the loud case and is covered above. The quiet
// case is a source that returns bytes that are not random. 16 zero bytes produce the published
// 'abandon ... about' phrase. On a buyer's device that would collapse the two-half scheme to one half
// with nothing visibly wrong, and the funding address would be computable by anyone from the card's
// printed public key. newMnemonic() is the one place all key generation goes through, so it is tested here.
{
  const { newMnemonic } = await import('./core.js');
  const realGRV = globalThis.crypto && globalThis.crypto.getRandomValues;
  const stub = fn => { globalThis.crypto.getRandomValues = fn; };
  const throwsRng = () => { try { newMnemonic(); return false; } catch (e) { return /RNG-01/.test(e.message); } };

  ok('a healthy generator produces words normally', (() => { try { return newMnemonic().split(' ').length === 12; } catch (e) { return false; } })());

  stub(a => a.fill(0));
  ok('a generator stuck at ZERO is refused (would be the abandon phrase)', throwsRng());

  stub(a => a.fill(255));
  ok('a generator stuck at 0xff is refused (would be the zoo phrase)', throwsRng());

  stub(a => a.fill(0x5a));
  ok('a generator stuck at an arbitrary constant is refused', throwsRng());

  // not byte-constant, but stuck: every DRAW is identical. Catching this needs two draws, not one.
  let counter = 0;
  stub(a => { for (let i = 0; i < a.length; i++) a[i] = (i * 7 + 3) & 255; counter++; return a; });
  ok('a generator returning the SAME draw every time is refused', throwsRng());
  ok('the stuck-draw case really was exercised (drew twice)', counter >= 2, 'drew ' + counter + ' times');

  // Every stub above yields two IDENTICAL draws, so the equal-draws check alone catches them all and the
  // constant-bytes check has no independent coverage: deleting it left this suite green. This stub returns
  // a DIFFERENT constant each call, so the draws differ and only the constant check can reject it.
  let step = 0;
  stub(a => { a.fill(step++ & 255); return a; });
  ok('a generator returning a DIFFERENT constant each draw is refused (isolates the constant check)', throwsRng());

  if (realGRV) globalThis.crypto.getRandomValues = realGRV;
  ok('the real generator still works after the stubs are removed', (() => { try { return newMnemonic().split(' ').length === 12; } catch (e) { return false; } })());
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
// A SKIP here is indistinguishable from a PASS at the suite summary, which would quietly remove the one
// tripwire aimed at already-printed key material. So absence is a FAILURE unless explicitly waived.
// Portability, external review finding 7: this defaulted to a private absolute path, so the advertised
// ten-suite command could not run cleanly on an auditor's machine. But a silent skip is what made this
// dangerous in the first place. So: if BITCARD_MANIFEST is set, the manifest MUST exist and pass. If it is
// not set and no local batch is present, the section reports NOT APPLICABLE on its own line, and the final
// summary says so too, so a reduced run can never be mistaken for a full one.
{
  const explicit = !!process.env.BITCARD_MANIFEST;
  const p = process.env.BITCARD_MANIFEST || 'C:/Users/Cameron/bitcard-mint/bitcard-print-300-QC-manifest.json';
  let man = null;
  try { man = JSON.parse(fs.readFileSync(p, 'utf8')); } catch (e) {}
  if (explicit) ok('BITCARD_MANIFEST points at a readable manifest', man !== null, 'not readable: ' + p);
  if (!man) {
    batchMode = 'NOT APPLICABLE (no minted batch on this machine)';
    console.log('  minted-batch audit: ' + batchMode);
    console.log('  to audit a real batch here, set BITCARD_MANIFEST to its QC-manifest.json');
  }
  if (man) {
    batchMode = 'audited ' + p;
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

// State the batch mode on the SUMMARY line, which is what test-all echoes. A reduced run must announce
// itself where the reader actually looks, not only in scrollback.
const modeNote = /^NOT APPLICABLE/.test(batchMode) ? ', minted-batch audit NOT APPLICABLE here' : ', minted batch audited';
console.log('\n' + (fail === 0 ? 'ENTROPY OK (' + pass + ' passed' + modeNote + ')' : 'ENTROPY FAILED (' + fail + ' failures)'));
process.exit(fail === 0 ? 0 : 1);
