// The published spec is what a third party reimplements from. If it contradicts the shipped code, an
// honest implementer writes a parser that rejects our own cards, and we look sloppy in front of exactly
// the people whose trust the open-standard story depends on.
//
// This caught nothing at the time it was written because the contradiction had just been fixed by hand;
// it exists so the NEXT format change cannot ship with the spec still describing the old one. External
// review, 2026-08-03: the spec intro still declared "a conformant parser reads exactly 41 bytes" for a
// full day after v2 shipped, while section 4.1 correctly documented both versions.
//
// Run: node test-spec-consistency.mjs
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { RECORD_V1_LEN, RECORD_V2_LEN, CHECKSUM_LEN } from './core.js';

let pass = 0, fail = 0;
const ok = (n, c, d) => { c ? pass++ : (fail++, console.log('FAIL: ' + n + (d !== undefined ? '\n      ' + d : ''))); };

// Both layouts must work: the dev tree (build/ beside release/) and the RELEASED repo, where build/ and
// spec/ are siblings. A path list that only resolves on the author's machine is the same portability trap
// as a test that silently skips: it turns green everywhere it cannot actually check anything.
const SPECS = ['../spec/bitcard-claim-spec.md', '../release/spec/bitcard-claim-spec.md', '../bitcard-claim-spec.md']
  .map(p => fileURLToPath(new URL(p, import.meta.url)))
  .filter(existsSync);
ok('at least one copy of the spec is present (checked dev and released layouts)', SPECS.length > 0);

for (const p of SPECS) {
  const name = p.split(/[\\/]/).slice(-2).join('/');
  const text = readFileSync(p, 'utf8');

  // both record lengths, as the code defines them, must appear
  ok(name + ': documents the v1 length (' + RECORD_V1_LEN + ')', text.includes(String(RECORD_V1_LEN)));
  ok(name + ': documents the v2 length (' + RECORD_V2_LEN + ')', text.includes(String(RECORD_V2_LEN)));
  ok(name + ': documents the checksum size (' + CHECKSUM_LEN + ' bytes)', /5[- ]byte|5 bytes/i.test(text));

  // A CONTRADICTION is a sentence that fixes the record at one length. These phrasings claim v1 is the
  // only format, which is exactly how an implementer ends up rejecting v2 cards.
  const contradictions = [
    [/reads exactly 41 bytes/i,            'says a conformant parser reads exactly 41 bytes'],
    [/only the 41-byte/i,                  'calls 41 bytes the only record'],
    [/the 41-byte record\)/i,              'names the 41-byte record as THE authoritative format'],
    [/record\(41\)\s*->\s*base64url_nopad\s*\/\/\s*41 bytes/i, 'shows a 41-byte-only encoding line'],
  ];
  for (const [re, why] of contradictions) {
    ok(name + ': does not contradict v2 (' + why + ')', !re.test(text),
       'found: ' + (text.match(re) || [''])[0]);
  }

  // the conformance rules a third party must follow
  ok(name + ': states both versions stay valid', /both are valid forever|MUST accept both|accepted forever|accept both/i.test(text));
  ok(name + ': states new cards must be v2', /MUST be minted as v2|new cards.{0,40}v2/i.test(text));
  ok(name + ': states the v2 checksum must be verified', /MUST verify the v2 checksum|verify the checksum/i.test(text));
}

// the frozen v2 vector in the published vectors file must match what the code builds
{
  const vp = ['../spec/bitcard-test-vectors.json', '../bitcard-test-vectors.json', '../release/spec/bitcard-test-vectors.json']
    .map(p => fileURLToPath(new URL(p, import.meta.url))).filter(existsSync);
  ok('published test vectors are present', vp.length > 0);
  for (const p of vp) {
    const v = JSON.parse(readFileSync(p, 'utf8'));
    const r2 = v.cardRecord && v.cardRecord.recordV2;
    const nm = p.split(/[\\/]/).slice(-1)[0];
    ok(nm + ': publishes a v2 record vector', !!r2);
    if (r2) {
      const { parseAndVerifyCard } = await import('./core.js');
      let parsed = null;
      try { parsed = parseAndVerifyCard(r2.cardURI); } catch (e) {}
      ok(nm + ': the published v2 vector parses with the shipped parser', parsed !== null && parsed.version === 2);
      ok(nm + ': publishes corruption vectors a parser must reject', Array.isArray(r2.corruptionVectors) && r2.corruptionVectors.length > 0);
      let rejected = 0;
      for (const cv of (r2.corruptionVectors || [])) {
        try { parseAndVerifyCard(cv.cardURI); } catch (e) { rejected++; }
      }
      ok(nm + ': every published corruption vector is actually rejected (' + rejected + '/' + (r2.corruptionVectors || []).length + ')',
         rejected === (r2.corruptionVectors || []).length);
    }
  }
}

console.log('\n' + (fail === 0 ? 'SPEC CONSISTENCY OK (' + pass + ' passed)' : 'SPEC CONSISTENCY FAILED (' + fail + ' failures)'));
process.exit(fail === 0 ? 0 : 1);
