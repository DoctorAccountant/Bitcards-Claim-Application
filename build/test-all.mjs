// The ONE command the release procedure runs. SOP-4 invokes this and nothing else, so a new test
// added here can never be forgotten in the SOP: the two cannot drift apart.
// Run: node test-all.mjs
import { execFileSync } from 'node:child_process';

const SUITES = [
  ['test-encoding.mjs',     [], 'encoding: no mojibake, templates and artifacts ASCII'],
  ['test-core.mjs',         [], 'crypto vectors and card record round-trip'],
  ['test-entropy.mjs',      [], 'key generation entropy path (the Coldcard failure class)'],
  ['test-mainnet.mjs',      [], 'mainnet address encoding'],
  ['test-paste.mjs',        [], 'card code and word input parsing, including ambiguous pastes'],
  ['test-hardening.mjs',    [], 'node trust, broadcast, fee and RBF bounds'],
  ['test-setup-parity.mjs', [], 'offline setup derives the same address the claim path opens'],
  ['test-claim-ui.mjs',     ['app-claim.bundle.js'],   'claim app money path and state machine'],
  ['test-offline-ui.mjs',   ['app-offline.bundle.js'], 'offline tool gating, setup safety and state'],
  ['test-recover.mjs',      [], 'python last-resort recovery agrees with the JS derivation'],
  ['test-derivation-differential.mjs', [], 'RANDOM mnemonics agree across the JS and python implementations'],
  ['test-batch-verifier.mjs', [], 'the printed-batch verifier is no more permissive than the app'],
  ['test-known-batch.mjs',    [], 'corrupted card codes are caught before anyone funds them'],
  ['test-record-v2.mjs',      [], 'v2 checksummed records + the v1 permanence pin'],
  ['test-spec-consistency.mjs', [], 'the published spec does not contradict the shipped parser'],
  ['test-mint-guards.mjs',    [], 'the mint refuses reused serials from any folder'],
];

let failed = [];
for (const [file, args, what] of SUITES) {
  process.stdout.write(file.padEnd(24));
  try {
    const out = execFileSync(process.execPath, [file, ...args], { encoding: 'utf8' });
    const last = out.trim().split('\n').filter(Boolean).pop() || '';
    console.log('PASS   ' + last.trim());
  } catch (e) {
    const out = String(e.stdout || e.message);
    const first = out.split('\n').find(l => l.startsWith('FAIL')) || out.trim().split('\n').pop();
    console.log('FAIL   ' + (first || '').trim());
    failed.push(file);
  }
}
console.log('\n' + (failed.length === 0
  ? 'ALL SUITES PASSED (' + SUITES.length + ' suites)'
  : 'FAILED SUITES: ' + failed.join(', ')));
process.exit(failed.length === 0 ? 0 : 1);
