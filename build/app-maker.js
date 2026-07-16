// Bitcard MAKER tool (spec v0.4). INTERNAL card factory. Generates each card's Part 1 + the QR record.
// v0.4: cards carry NO issuer signature, so this tool holds NO persistent key. The only secret it
// produces is each card's per-card Part 1 (sealed on the card and destroyed after manufacture, §2a).
import { $, log, NET, bip39, wordlist, hexlib, b64u,
  buildRecord, parseCard, halfScalar, pubOfScalar, showBuildHash } from './core.js';

window.addEventListener('error', e => { const s=document.getElementById('status'); if(s) s.textContent='BUNDLE ERROR: '+(e.message||(e.error&&e.error.message)||e); });

let serialCounter = 1;

function makeCardURI(P1bytes, serial){
  return 'bitcard:' + b64u.encode(buildRecord(P1bytes, serial));
}

function runSelfTest(){
  try{
    const P1 = pubOfScalar(halfScalar(bip39.generateMnemonic(wordlist,128)));
    const uri = makeCardURI(P1, 7);
    let ok = false;
    try{ const v = parseCard(uri); ok = v.P1hex === hexlib.encode(P1) && v.serial === 7; }catch(e){}
    const el = $('selftest'); el.textContent = 'freshly generated card parses + P1/serial round-trip: ' + ok + '\n\n';
    const sp = document.createElement('span'); sp.className = ok ? 'ok' : 'bad';
    sp.textContent = ok ? '✓ SELF-TEST PASS' : '✗ SELF-TEST FAIL';
    el.appendChild(sp);
  }catch(e){ log('selftest','self-test error: '+e.message,'bad'); console.error(e); }
}

function init(){
  $('genCard').onclick = ()=>{
    try{
      const m1 = bip39.generateMnemonic(wordlist,128);
      const P1 = pubOfScalar(halfScalar(m1));
      const serial = serialCounter++;
      const uri = makeCardURI(P1, serial);
      $('cardOut').textContent =
        'Part 1 mnemonic (SEAL on the card, then DESTROY this maker copy — §2a):\n  '+m1+'\n\n'+
        'serial: '+serial+'\n\n'+
        'QR content (card record — the claim app validates its structure):\n  '+uri;
    }catch(e){ log('cardOut','error: '+e.message,'bad'); }
  };

  log('status','maker tool ✓ ['+NET.label+'] (card factory · v0.4, no issuer key · create-only · INTERNAL. Sealed-word check is the separate qc-tool.html)','ok');
  showBuildHash();
  runSelfTest();
}

if(document.readyState !== 'loading') init();
else document.addEventListener('DOMContentLoaded', init);
