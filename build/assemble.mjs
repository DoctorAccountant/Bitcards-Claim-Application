import fs from 'node:fs';
import crypto from 'node:crypto';
// Usage: node assemble.mjs <template.html> <bundle.js> <out.html>
const tpl = process.argv[2] || 'build/template-claim.html';
const bnd = process.argv[3] || 'build/app-claim.bundle.js';
const out = process.argv[4] || 'print/claim-app.html';

let template = fs.readFileSync(tpl, 'utf8');
let bundle = fs.readFileSync(bnd, 'utf8');

// Brand fonts, inlined as data: URIs so the app stays ONE self-contained file with no external requests
// (strict CSP forbids remote fonts; the page must also work from a saved local copy with no network).
// Latin subsets only. Each file is a variable font covering the weights listed, so 3 files cover the whole UI.
const FONT_DIR = 'C:/Users/Cameron/OneDrive - Accountant Doctor/Documents/bitcard/site/fonts/';
const FONTS = [
  { family: 'Archivo',       weight: '600 700', file: 'k3kPo8UDI-1M0wlSV9XAw6lQkqWY8Q82sLydOxI.woff2' },
  { family: 'Inter Tight',   weight: '400 600', file: 'NGSwv5HMAFg6IuGlBNMjxLsH8ag.woff2' },
  { family: 'IBM Plex Mono', weight: '400',     file: '-F63fjptAgt5VM-kVkqdyU8n1i8q1w.woff2' }
];
if (template.includes('<!--FONTS-->')) {
  const css = FONTS.map(f => {
    const b64 = fs.readFileSync(FONT_DIR + f.file).toString('base64');
    return `@font-face{font-family:'${f.family}';font-style:normal;font-weight:${f.weight};font-display:swap;` +
           `src:url(data:font/woff2;base64,${b64}) format('woff2');` +
           `unicode-range:U+0000-00FF,U+0131,U+0152-0153,U+02BB-02BC,U+02C6,U+02DA,U+02DC,U+2000-206F,U+2074,U+20AC,U+2122,U+2191,U+2193,U+2212,U+2215,U+FEFF,U+FFFD;}`;
  }).join('\n');
  template = template.replace('<!--FONTS-->', () => css);
  console.log('fonts inlined:', FONTS.length, 'families,', Math.round(css.length / 1024), 'KB base64');
}
if (bundle.includes('</script>')) throw new Error('bundle contains </script> — escaping would break the self-hash; investigate.');
// CSP hardening (spec §10 P1): pin script-src from broad 'unsafe-inline' to the exact sha256 of the inlined bundle.
const scriptHash = crypto.createHash('sha256').update(bundle, 'utf8').digest('base64');
const tightened = template.replace("script-src 'unsafe-inline'", "script-src 'sha256-" + scriptHash + "'");
// Inline verbatim (no added whitespace) so runtime sha256(script.textContent) === sha256(bundle).
// IMPORTANT: function replacer — a string replacement would interpret $&, $$, etc. in the minified bundle and corrupt it.
const html = tightened.replace('<!--APPSCRIPT-->', () => '<script id="appbundle">' + bundle + '</script>');
fs.writeFileSync(out, html);

// Historical tripwire: v0.2-v0.3 builds carried a DEMO maker signing key with this literal value. v0.4 removed the
// maker key entirely, so this must NEVER appear in any bundle; the check below stays as a cheap regression guard.
const MAKER_PRIV_HEX = '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff';
console.log('written:', out, '·', html.length, 'bytes');
console.log('external <script src=>:', (html.match(/<script\s+src=/g) || []).length);
console.log('esm.sh refs:', (html.match(/esm\.sh/g) || []).length);
console.log('has CSP meta:', /Content-Security-Policy/.test(html));
console.log('contains DEMO maker PRIVATE key:', html.includes(MAKER_PRIV_HEX));   // MUST be false for the claim app
console.log('runtime https refs:', [...new Set(html.match(/https:\/\/[a-z0-9.\/]+/gi) || [])].join('  '));
console.log("CSP script-src 'unsafe-inline' removed:", !/script-src 'unsafe-inline'/.test(html));
console.log('CSP script-src pin:', 'sha256-' + scriptHash);
const _m = html.match(/<script id="appbundle">([\s\S]*?)<\/script>/);
console.log('CSP hash matches inlined script (app will load):', _m ? crypto.createHash('sha256').update(_m[1], 'utf8').digest('base64') === scriptHash : false);
