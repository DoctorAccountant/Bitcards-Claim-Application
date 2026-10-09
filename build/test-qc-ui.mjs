// Drive the real bundled manufacturing QC page against a minimal DOM. This pins the physical workflow:
// scanners return the full printed HTTPS URL, operator/witness IDs are mandatory, words are cleared on
// every path, and the exported public audit contains no mnemonic.
import fs from 'node:fs';

const BUNDLE = process.argv[2];
if (!BUNDLE) { console.error('usage: node test-qc-ui.mjs <app-qc.bundle.js>'); process.exit(1); }

const IDS = ['status','buildhash','selftest','operator','witness','sealWords','sealUri','verifyCardBtn',
  'verifyCardOut','destroyBtn','destroyOut','auditOut','exportBtn','exportOut','appbundle'];

function element(id) {
  return {
    id, value: '', textContent: '', className: '', href: '', download: '', onclick: null,
    appendChild(child) { this.textContent += child.textContent || ''; },
    click() {}
  };
}

const els = Object.fromEntries(IDS.map(id => [id, element(id)]));
globalThis.document = {
  readyState: 'complete',
  getElementById: id => els[id] || null,
  createElement: () => element('created')
};
globalThis.window = { addEventListener() {} };

const source = fs.readFileSync(BUNDLE, 'utf8');
new Function(source)();

let pass = 0, fail = 0;
const ok = (name, condition, detail = '') => condition ? pass++ : (fail++, console.log('FAIL: ' + name + (detail ? '\n      ' + detail : '')));

ok('self-test passes', /SELF-TEST PASS/.test(els.selftest.textContent), JSON.stringify(els.selftest.textContent));
ok('status identifies offline keyless tool', /KEYLESS.*offline/i.test(els.status.textContent));
for (const forbidden of ['fetch(', 'XMLHttpRequest', 'WebSocket', 'sendBeacon', 'blockstream.info', 'mempool.space']) {
  ok('bundle excludes network capability: ' + forbidden, !source.includes(forbidden));
}

const fullUrl = 'https://bitcardssetup.com/app.html#AQABAQPZAvNfVg4EcMYzE8c2kWjZ198tSb8pX9n7fLEJzO4ElAAAAHs';
const part1 = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

// Missing identities must fail before a result can enter the audit.
els.sealUri.value = fullUrl;
els.sealWords.value = part1;
els.verifyCardBtn.onclick();
ok('missing operator/witness is refused', /enter both the operator ID and witness ID/i.test(els.verifyCardOut.textContent));
ok('refused attempt does not enter audit', /no cards checked yet/i.test(els.auditOut.textContent));
ok('words clear after refused attempt', els.sealWords.value === '');

// The actual QR contains a full HTTPS URL, not a bitcard: URI.
els.operator.value = 'operator-1';
els.witness.value = 'witness-1';
els.sealWords.value = part1;
els.verifyCardBtn.onclick();
ok('full printed HTTPS QR is accepted', /MATCH.*serial 123/i.test(els.verifyCardOut.textContent));
ok('successful read-back enters PASS audit', /PASS\s+serial 123/i.test(els.auditOut.textContent));
ok('successful read-back words clear', els.sealWords.value === '');

els.destroyBtn.onclick();
ok('destruction sign-off is recorded', /destruction recorded for serial 123/i.test(els.destroyOut.textContent));
ok('audit no longer says destruction NO', /destroyed:yes/i.test(els.auditOut.textContent));

els.exportBtn.onclick();
let report = null;
try { report = JSON.parse(els.exportOut.textContent); } catch (e) {}
ok('audit export is valid JSON', report && report.count === 1 && report.records.length === 1);
ok('audit records exact operator and witness', report && report.records[0].operator === 'operator-1' && report.records[0].witness === 'witness-1');
ok('audit records full public record and hash', report && /^[0-9a-f]+$/.test(report.records[0].recordHex) && /^[0-9a-f]{64}$/.test(report.records[0].recordSha256));
ok('audit export contains no mnemonic', !els.exportOut.textContent.includes('abandon'));

// A different valid phrase is a loud mismatch, never another PASS or destruction candidate.
els.sealWords.value = 'legal winner thank year wave sausage worth useful legal winner thank yellow';
els.verifyCardBtn.onclick();
ok('valid words from another card are a MISMATCH', /MISMATCH.*DO NOT SHIP/i.test(els.verifyCardOut.textContent));
ok('mismatched words clear', els.sealWords.value === '');
els.destroyBtn.onclick();
ok('mismatch cannot receive destruction sign-off', /run a verify that returns MATCH first/i.test(els.destroyOut.textContent));

console.log('\n' + (fail === 0 ? 'QC UI OK (' + pass + ' passed)' : 'QC UI FAILED (' + fail + ' failures)'));
process.exit(fail === 0 ? 0 : 1);
