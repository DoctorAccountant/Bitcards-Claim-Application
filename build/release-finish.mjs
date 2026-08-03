// SOP-4 step 5: verify the LIVE site serves exactly the bytes we built, then update the monitor config.
//
// This used to be manual: read hashes off the screen, retype them into monitor/expected-hashes.json.
// Two ways that fails silently. Retype a hash wrong and the monitor alarms forever, so it gets ignored or
// switched off, and the one tripwire watching for a hostile deploy is gone. Update the file WITHOUT
// checking the live site and the monitor is now blessing whatever is actually deployed, including bytes
// nobody built. So: fetch first, compare against the local build, and only write on a full match.
//
// Run AFTER deploying:  node release-finish.mjs [--commit <sha>]
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { execSync } from 'node:child_process';

const ROOT = new URL('../', import.meta.url);
const CFG = new URL('monitor/expected-hashes.json', ROOT);

// what the live URL SHOULD serve <- the file we actually built, byte for byte
const LOCAL = { 'app.html': 'build/claim-app.html', 'offline.html': 'build/offline.html' };

const sha = buf => createHash('sha256').update(buf).digest('hex');
const cfg = JSON.parse(readFileSync(CFG, 'utf8'));

const want = {};
for (const [name, rel] of Object.entries(LOCAL)) want[name] = sha(readFileSync(new URL(rel, ROOT)));

console.log('locally built:');
for (const [n, h] of Object.entries(want)) console.log('  ' + n.padEnd(14) + h);

let bad = 0, unreachable = 0;
console.log('\nlive:');
for (const u of cfg.urls) {
  const name = u.split('/').pop();
  if (!want[name]) { console.log('  ' + u + '  (no local counterpart, skipped)'); continue; }
  let got;
  try {
    const r = await fetch(u, { cache: 'no-store' });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    got = sha(Buffer.from(await r.arrayBuffer()));
  } catch (e) { unreachable++; console.log('  UNREACHABLE ' + u + '  ' + e.message); continue; }
  const okNow = got === want[name];
  if (!okNow) bad++;
  console.log('  ' + (okNow ? 'match  ' : 'STALE  ') + u + (okNow ? '' : '\n           serving ' + got));
}

if (bad || unreachable) {
  console.error('\nREFUSING to update monitor/expected-hashes.json: ' +
    (bad ? bad + ' url(s) do not serve the built bytes' : '') + (bad && unreachable ? ' and ' : '') +
    (unreachable ? unreachable + ' unreachable' : '') + '.');
  console.error(bad ? 'The deploy did not land, or landed somewhere else. Do not edit the file by hand.'
                    : 'Re-run when the network is back. Nothing was changed.');
  process.exit(1);
}

let commit = cfg.releaseCommit;
const i = process.argv.indexOf('--commit');
if (i > -1 && process.argv[i + 1]) commit = process.argv[i + 1];
else { try { commit = execSync('git rev-parse --short HEAD', { cwd: new URL('.', ROOT).pathname.slice(1) }).toString().trim() || commit; } catch (e) {} }

cfg.artifacts = want;
cfg.updated = new Date().toISOString().slice(0, 10);
cfg.releaseCommit = commit;
writeFileSync(CFG, JSON.stringify(cfg, null, 2) + '\n');
console.log('\nEvery live URL serves the built bytes. monitor/expected-hashes.json updated (commit ' + commit + ').');
console.log('Now run: powershell -File monitor/bitcard-hash-monitor.ps1   (expect OK)');
