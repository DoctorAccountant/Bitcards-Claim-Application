// Bitcard QC / ceremony tool (spec §2a, v0.4). KEYLESS — imports ONLY public operations from core.js.
// No maker key, no card creation. Confirms each physical card's printed words reproduce its QR public key before sealing.
import { $, log, NET, hexlib, sha256, parseAndVerifyCard, buildRecord, halfScalar, pubOfScalar, b64u, normCardInput, normWords, showBuildHash } from './core.js';

window.addEventListener('error', e => { const s=document.getElementById('status'); if(s) s.textContent='BUNDLE ERROR: '+(e.message||(e.error&&e.error.message)||e); });

const audit = [];
let pending = null; // last MATCH awaiting destruction sign-off

function nowStamp(){ return new Date().toISOString().replace('T',' ').slice(0,19); }

function renderAudit(){
  const pass = audit.filter(a=>a.result==='PASS').length, fail = audit.length - pass;
  const undestroyed = audit.filter(a=>a.result==='PASS' && !a.destroyed).length;
  $('auditOut').textContent = audit.length
    ? ('batch — '+audit.length+' checked · '+pass+' PASS · '+fail+' FAIL · '+undestroyed+' PASS awaiting destruction sign-off\n' +
       audit.map(a=> a.result+'  serial '+a.serial+'  P1 '+a.p1.slice(0,16)+'…  destroyed:'+(a.destroyed?('yes '+a.destroyedAt):'NO')+'  '+a.t).join('\n'))
    : '(no cards checked yet)';
}

function runSelfTest(){
  try{
    const words = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
    const P1 = pubOfScalar(halfScalar(words));
    const uri = 'bitcard:' + b64u.encode(buildRecord(P1, 1));
    const cardP1 = parseAndVerifyCard(uri).P1hex;
    const matchOK = hexlib.encode(P1) === cardP1;                                     // correct words reproduce the card key
    const wrongWords = 'legal winner thank year wave sausage worth useful legal winner thank yellow';
    const mismatchOK = hexlib.encode(pubOfScalar(halfScalar(wrongWords))) !== cardP1; // different valid words do NOT
    let malformedOK = false; try{ parseAndVerifyCard(uri.slice(0, uri.length-4)); }catch(e){ malformedOK = true; }
    const pass = matchOK && mismatchOK && malformedOK;
    const el = $('selftest');
    el.textContent = 'correct printed words reproduce the card key: '+matchOK+'\ndifferent words detected as mismatch: '+mismatchOK+'\nmalformed QR rejected: '+malformedOK+'\n\n';
    const sp = document.createElement('span'); sp.className = pass ? 'ok' : 'bad';
    sp.textContent = pass ? '✓ SELF-TEST PASS' : '✗ SELF-TEST FAIL';
    el.appendChild(sp);
  }catch(e){ log('selftest','self-test error: '+e.message,'bad'); console.error(e); }
}

function init(){
  $('verifyCardBtn').onclick = ()=>{
    try{
      const operator = $('operator').value.trim();
      const witness = $('witness').value.trim();
      if(!operator || !witness) throw new Error('enter both the operator ID and witness ID before checking a card');
      // A scanner normally returns the full HTTPS URL printed in the QR. Normalize through the exact
      // customer-app input path so QC cannot reject a card that the customer app accepts (or vice versa).
      const uri = normCardInput($('sealUri').value);
      const words = normWords($('sealWords').value);
      const card = parseAndVerifyCard(uri);                          // parse + validate the card record (throws if malformed)
      const record = b64u.decode(uri.slice('bitcard:'.length));      // complete v1 (41-byte) or v2 (46-byte) record
      const reP1 = hexlib.encode(pubOfScalar(halfScalar(words)));    // re-derive P1 from the words read off the physical card
      const ok = reP1 === card.P1hex;
      const rec = {
        serial: card.serial,
        p1: card.P1hex,
        recordHex: hexlib.encode(record),
        recordSha256: hexlib.encode(sha256(record)),
        result: ok ? 'PASS' : 'FAIL',
        t: nowStamp(),
        operator,
        witness,
        destroyed: false,
        destroyedAt: null
      };
      audit.push(rec);
      pending = ok ? rec : null;
      log('verifyCardOut', ok
        ? '✓ MATCH — serial '+card.serial+'. The sealed words reproduce the card\'s public key. Destroy the maker copy of Part 1, then click "Confirm destruction" to complete this card\'s audit record.'
        : '✗ MISMATCH — serial '+card.serial+'. Sealed words do NOT reproduce the card\'s key. DO NOT SHIP. Re-check the read-back; if the physical seal is wrong, destroy the card and remake it.',
        ok ? 'ok' : 'bad');
      renderAudit();
    }catch(e){ log('verifyCardOut','error: '+e.message+' (is the QR a valid card record, and the words valid BIP39?)','bad'); }
    finally{ $('sealWords').value = ''; }   // clear the read-back words on EVERY path (success or error)
  };

  $('destroyBtn').onclick = ()=>{
    if(!pending){ log('destroyOut','run a verify that returns MATCH first (only a matched card can have its maker copy signed off as destroyed)','bad'); return; }
    pending.destroyed = true; pending.destroyedAt = nowStamp();
    log('destroyOut','✓ destruction recorded for serial '+pending.serial+' at '+pending.destroyedAt,'ok');
    pending = null;
    renderAudit();
  };

  $('exportBtn').onclick = ()=>{
    const rep = { tool:'bitcard-qc', spec:'v0.4', operator:$('operator').value.trim()||'(unset)', witness:$('witness').value.trim()||'(unset)', exportedAt:nowStamp(), count:audit.length, records:audit };
    const json = JSON.stringify(rep, null, 2);
    $('exportOut').textContent = json;   // visible export (always works — copy/save manually)
    try{
      const blob = new Blob([json], {type:'application/json'});
      const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'bitcard-qc-audit.json'; a.click();
      setTimeout(()=>URL.revokeObjectURL(a.href), 1000);
    }catch(e){ /* if a download is blocked, the JSON above is the export */ }
  };

  log('status','QC / ceremony tool ✓ ['+NET.label+'] (KEYLESS · no maker key · no card creation · offline)','ok');
  showBuildHash();
  renderAudit();
  runSelfTest();
}

if(document.readyState !== 'loading') init();
else document.addEventListener('DOMContentLoaded', init);
