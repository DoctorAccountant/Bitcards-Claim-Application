import fs from 'node:fs';
import crypto from 'node:crypto';
// Usage: node assemble.mjs <template.html> <bundle.js> <out.html>
const tpl = process.argv[2] || 'build/template-claim.html';
const bnd = process.argv[3] || 'build/app-claim.bundle.js';
const out = process.argv[4] || 'print/claim-app.html';

const template = fs.readFileSync(tpl, 'utf8');
let bundle = fs.readFileSync(bnd, 'utf8');
if (bundle.includes('</script>')) throw new Error('bundle contains </script> — escaping would break the self-hash; investigate.');
// CSP hardening (spec §10 P1): pin script-src from broad 'unsafe-inline' to the exact sha256 of the inlined bundle.
const scriptHash = crypto.createHash('sha256').update(bundle, 'utf8').digest('base64');
const tightened = template.replace("script-src 'unsafe-inline'", "script-src 'sha256-" + scriptHash + "'");
// Inline verbatim (no added whitespace) so runtime sha256(script.textContent) === sha256(bundle).
// IMPORTANT: function replacer — a string replacement would interpret $&, $$, etc. in the minified bundle and corrupt it.
const html = tightened.replace('<!--APPSCRIPT-->', () => '<script id="appbundle">' + bundle + '</script>');
fs.writeFileSync(out, html);

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
