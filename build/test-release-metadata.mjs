import { readFileSync } from 'node:fs';
import { rewriteReadmeHashes } from './release-metadata.mjs';

let pass=0, fail=0;
const ok=(name,cond)=>{ cond ? pass++ : (fail++,console.log('FAIL: '+name)); };
const local={ 'app.html':'build/claim-app.html', 'offline.html':'build/offline.html' };
const want={ 'app.html':'a'.repeat(64), 'offline.html':'b'.repeat(64) };
const original=readFileSync(new URL('../README.md',import.meta.url),'utf8');
const sentinel='0'.repeat(64);
const stale=original.replace(/(sha256 of app\/claim-app\.html:\r?\n)[0-9a-f]{64}/i,'$1'+sentinel)
                    .replace(/(sha256 of app\/offline\.html:\r?\n)[0-9a-f]{64}/i,'$1'+sentinel);
const rewritten=rewriteReadmeHashes(stale,want,local);
ok('claim hash sentinel is replaced',!rewritten.includes('sha256 of app/claim-app.html:\n'+sentinel) && rewritten.includes(want['app.html']));
ok('offline hash sentinel is replaced',rewritten.includes(want['offline.html']));
let missingFailed=false;
try{ rewriteReadmeHashes(stale.replace('sha256 of app/claim-app.html:','claim hash removed:'),want,local); }catch(e){ missingFailed=true; }
ok('missing mandatory README field fails closed',missingFailed);
console.log(fail?'RELEASE METADATA FAILED ('+fail+' failures)':'RELEASE METADATA OK ('+pass+' passed)');
process.exit(fail?1:0);
