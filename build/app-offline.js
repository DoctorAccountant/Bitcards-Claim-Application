// Bitcard OFFLINE key tool (spec v0.4). Combines the two halves and shows the card's private key (WIF) so it can be
// swept with a standard wallet. It NEVER touches the network: it imports only pure crypto + DOM helpers from core.js
// (no getUtxos / broadcastTx / fetch), and its page CSP is connect-src 'none'. Works with EXISTING v0.4 cards unchanged.
// Copy rules: no em dashes; JS single-quoted strings avoid apostrophes.
import { $, log, NET, bip39, wordlist, halfScalar, pubOfScalar, combine, parseAndVerifyCard, toWIF, hexlib, showBuildHash } from './core.js';

window.addEventListener('error', e => { const s=document.getElementById('status'); if(s) s.textContent='BUNDLE ERROR: '+(e.message||(e.error&&e.error.message)||e); });

function normWords(s){ return (s||'').trim().toLowerCase().replace(/\s+/g,' '); }
function checkWords(raw, boxName){
  const m = normWords(raw);
  const words = m ? m.split(' ') : [];
  if(words.length !== 12) return { err: 'The '+boxName+' has '+words.length+(words.length===1?' word':' words')+', it needs exactly 12.' };
  for(let i=0;i<12;i++){ if(wordlist.indexOf(words[i]) < 0) return { err: 'In the '+boxName+', word '+(i+1)+' is not on the standard word list. Check it against the card.' }; }
  try{ halfScalar(m); }catch(e){ return { err: 'The '+boxName+' does not pass its built-in check. Compare it against the card word by word.' }; }
  return { m };
}

// Remove any produced key from the DOM. Called before every attempt, on error, on card/word change, on Done, on pagehide.
function clearResult(){ $('outAddr').textContent = ''; $('outWif').textContent = ''; $('resultBox').classList.add('hide'); }

function init(){
  const isMain = NET.hrp === 'bc';
  document.title = 'Bitcard offline key tool (' + NET.label + ')';
  const nb = $('netbadge');
  if(nb){ nb.textContent = isMain ? 'Real bitcoin · mainnet' : 'TESTNET · practice';
    nb.style.cssText = 'font-size:11px;font-weight:800;border-radius:999px;padding:3px 10px;white-space:nowrap;' + (isMain ? 'background:#E07B12;color:#fff' : 'background:#eee;color:#555'); }

  // The "trust no website" promise only holds when this file runs from a SAVED copy (file://). Served live over the
  // web, a compromised host could ship a modified page, so we REFUSE secret entry and require download-then-open-offline.
  const LIVE = (location.protocol !== 'file:');
  if(LIVE){
    ['p1','p2','revealBtn'].forEach(id => { const el=$(id); if(el) el.disabled = true; });
    const rb = $('revealBtn'); if(rb) rb.textContent = 'Save this page, then open it offline to use it';
    const g = $('liveGate'); if(g) g.classList.remove('hide');
  }

  try{ const h = (location.hash||'').replace(/^#/,'').trim(); if(h){ $('cardUri').value = h.startsWith('bitcard:') ? h : ('bitcard:'+h); } }catch(e){}
  function refreshCardStatus(){
    const val = $('cardUri').value.trim();
    if(!val){ $('cardStatus').textContent = ''; return; }
    try{ const c = parseAndVerifyCard(val); $('cardStatus').textContent = '✓ card loaded (No. '+c.serial+')'; }
    catch(e){ $('cardStatus').textContent = 'That code is not complete yet. Scan the QR on the back of the card, or paste the whole code.'; }
  }
  $('cardUri').addEventListener('input', ()=>{ refreshCardStatus(); clearResult(); });   // a new card must not leave the old key on screen
  refreshCardStatus();

  function wireCounter(inp,out){ const el=$(inp),o=$(out); el.addEventListener('input',()=>{ const t=el.value.trim(); const n=t?t.split(/\s+/).length:0; o.textContent=n?(n+' of 12 words'):''; $('keyOut').textContent=''; clearResult(); }); }
  wireCounter('p2','wc2'); wireCounter('p1','wc1');

  $('revealBtn').onclick = ()=>{
    clearResult(); $('keyOut').textContent = '';   // never let a previous key survive a new or failed attempt
    let card;
    try{ card = parseAndVerifyCard($('cardUri').value); }
    catch(e){ log('keyOut','First scan or paste the card code (the QR on the back of the card).','bad'); return; }
    const r2 = checkWords($('p2').value, 'handwritten box'); if(r2.err){ log('keyOut', r2.err, 'bad'); return; }
    const r1 = checkWords($('p1').value, 'scratch-panel box'); if(r1.err){ log('keyOut', r1.err, 'bad'); return; }
    // pairing: the scratch-panel words MUST reproduce this card's public key, or it is the wrong card / a typo
    let d1;
    try{
      d1 = halfScalar(r1.m);
      if(hexlib.encode(pubOfScalar(d1)) !== card.P1hex){
        log('keyOut','The words under the scratch panel do not match this card. Re-check the scratch-panel box word by word, and make sure the card code above matches this card.','bad');
        return;
      }
    }catch(e){ log('keyOut','Could not read the scratch-panel words: '+e.message,'bad'); return; }
    let out;
    try{ out = combine(d1, halfScalar(r2.m)); }
    catch(e){ log('keyOut','Something went wrong combining the two halves: '+e.message,'bad'); return; }
    const wif = toWIF(out.d);
    $('outAddr').textContent = out.address;
    $('outWif').textContent = wif;
    // clear the secret word inputs from the screen once the key is produced
    $('p1').value = ''; $('p2').value = ''; $('wc1').textContent = ''; $('wc2').textContent = '';
    $('resultBox').classList.remove('hide');
    try{ out.d = 0n; d1 = 0n; }catch(e){}
  };

  $('copyWif').onclick = ()=>{
    try{ navigator.clipboard.writeText($('outWif').textContent); const b=$('copyWif'); b.textContent='copied, clear your clipboard after use'; setTimeout(()=>{ b.textContent='copy'; },2500); }
    catch(e){ log('keyOut','Copy is not available here. Select the key text by hand.','bad'); }
  };
  $('clearBtn').onclick = ()=>{ clearResult(); $('keyOut').textContent = ''; };
  window.addEventListener('pagehide', ()=>{ try{ clearResult(); $('p1').value=''; $('p2').value=''; }catch(e){} });

  showBuildHash();
  const st = $('status'); if(st) st.textContent = LIVE ? 'download this page and open it offline to unlock it' : 'ready (running offline)';
}
init();
