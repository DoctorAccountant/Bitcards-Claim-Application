// RETIRED browser maker. A browser page cannot atomically reserve serials in the versioned allocation
// ledger, so allowing it to mint would make reuse possible on every reload or copied machine. Production
// cards are created only by mint-pilot-csv.mjs after an explicit ledger reservation.
import { $, log, NET, showBuildHash, verifyFrozenVector } from './core.js';

window.addEventListener('error', e => { const s=document.getElementById('status'); if(s) s.textContent='BUNDLE ERROR: '+(e.message||(e.error&&e.error.message)||e); });

function runSelfTest(){
  try{
    const ok = verifyFrozenVector().ok;
    const el = $('selftest'); el.textContent = 'published derivation vectors: ' + ok + '\n\n';
    const sp = document.createElement('span'); sp.className = ok ? 'ok' : 'bad';
    sp.textContent = ok ? '✓ SELF-TEST PASS' : '✗ SELF-TEST FAIL';
    el.appendChild(sp);
  }catch(e){ log('selftest','self-test error: '+e.message,'bad'); console.error(e); }
}

function init(){
  const button = $('genCard');
  button.disabled = true;
  button.textContent = 'Browser minting retired';
  $('cardOut').textContent = 'This page cannot create cards. Use the reviewed mint-pilot-csv.mjs process, which uses guarded randomness and the versioned serial-allocation ledger.';

  log('status','browser maker retired ['+NET.label+']. Production minting is CLI-only so serial reservations and entropy gates cannot be bypassed.','ok');
  showBuildHash();
  runSelfTest();
}

if(document.readyState !== 'loading') init();
else document.addEventListener('DOMContentLoaded', init);
