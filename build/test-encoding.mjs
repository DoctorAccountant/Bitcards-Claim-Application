// Encoding gate. A UTF-8 file read with a Windows codepage and rewritten as UTF-8 silently turns
// emoji and arrows into things like "ðŸŽ" and "â†". That shipped to
// production once (the chooser icons and Back arrows), so this now fails the build instead.
//
// Rule: build sources and shipped artifacts are ASCII-only where practical. Non-ASCII that must exist
// (checkmarks in JS strings) is escaped to \uXXXX by esbuild --charset=ascii, so the BUILT files are
// pure ASCII regardless. Templates must be ASCII: use HTML entities for glyphs.
//
// Run: node test-encoding.mjs
import fs from 'node:fs';

let pass = 0, fail = 0;
const ok = (name, cond, detail) => { cond ? pass++ : (fail++, console.log('FAIL: ' + name + (detail ? '\n      ' + detail : ''))); };

// Byte sequences that only appear when UTF-8 has been double-encoded.
const MOJIBAKE = [
  ['Ã°Å¸', 'emoji mangled (C3 B0 C5 B8)'],
  ['ðŸ', 'emoji mangled (F0 -> "ðŸ")'],
  ['â†', 'arrow mangled ("â†")'],
  ['â€', 'punctuation mangled ("â€")'],
  ['Â ', 'non-breaking space mangled'],
  ['�', 'replacement character (lost bytes)']
];

const TEMPLATES = ['template-claim.html', 'template-offline.html', 'template-maker.html', 'template-qc.html'];
const SOURCES   = ['app-claim.js', 'app-offline.js', 'app-qc.js', 'core.js', 'net.js', 'config.js'];
const BUILT     = ['claim-app.html', 'offline.html', '../print/qc-tool.html'];

const readIf = f => { try { return fs.readFileSync(new URL(f, import.meta.url), 'utf8'); } catch (e) { return null; } };

for (const f of [...TEMPLATES, ...SOURCES, ...BUILT]) {
  const s = readIf(f);
  if (s === null) continue;
  for (const [seq, label] of MOJIBAKE) {
    ok(f + ': no ' + label, !s.includes(seq));
  }
}

// Templates must be pure ASCII: any glyph belongs in an HTML entity so no editor or shell can corrupt it.
for (const f of TEMPLATES) {
  const s = readIf(f);
  if (s === null) continue;
  const bad = [...new Set([...s].filter(c => c.charCodeAt(0) > 126))];
  ok(f + ': template is ASCII-only',
     bad.length === 0,
     bad.length ? 'found: ' + bad.map(c => JSON.stringify(c) + ' U+' + c.charCodeAt(0).toString(16).toUpperCase().padStart(4, '0')).join(' ') + '  (use HTML entities)' : '');
}

// The shipped artifacts must be ASCII-only end to end, which also proves esbuild --charset=ascii ran.
for (const f of BUILT) {
  const s = readIf(f);
  if (s === null) continue;
  const bad = [...new Set([...s].filter(c => c.charCodeAt(0) > 126))];
  ok(f + ': built artifact is ASCII-only', bad.length === 0,
     bad.length ? 'found: ' + bad.slice(0, 8).map(c => 'U+' + c.charCodeAt(0).toString(16).toUpperCase().padStart(4, '0')).join(' ') : '');
}

// The chooser icons and Back arrows must actually be present as entities (proves the fix is in place).
{
  const s = readIf('template-claim.html');
  if (s) {
    ok('chooser gift icon present as entity', s.includes('&#x1F381;'));
    ok('chooser money icon present as entity', s.includes('&#x1F4B0;'));
    ok('back arrows present as entities', (s.match(/&larr;/g) || []).length >= 3);
  }
}

console.log('\n' + (fail === 0 ? 'ENCODING OK (' + pass + ' passed)' : 'ENCODING FAILED (' + fail + ' failures)'));
process.exit(fail === 0 ? 0 : 1);
