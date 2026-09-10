// Bitcard OFFLINE tool (spec v0.4). Two modes, both fully on-device:
//   SETUP: makes the buyer's 12 words and derives the card's deposit address from the card's PUBLIC half. The sealed
//          half is never needed, so a card can be set up and funded without any website seeing the address (this closes
//          the setup-time trust gap: a compromised web app could otherwise display an attacker's deposit address).
//   OPEN:  combines both halves and shows the card's private key (WIF) to sweep with a standard wallet.
// It NEVER touches the network: imports only pure crypto + DOM helpers from core.js (no getUtxos / broadcastTx / fetch),
// page CSP is connect-src 'none'. Works with EXISTING v0.4 cards unchanged (public record in, no card change needed).
// Copy rules: no em dashes; JS single-quoted strings avoid apostrophes.
import { $, log, NET, bip39, wordlist, halfScalar, pubOfScalar, setupAddress, combine, parseAndVerifyCard, normCardInput, normWords, toWIF, hexlib, showBuildHash, verifyFrozenVector, knownCardStatus, newMnemonic } from './core.js';

window.addEventListener('error', e => { const s=document.getElementById('status'); if(s) s.textContent='BUNDLE ERROR: '+(e.message||(e.error&&e.error.message)||e); });

function checkWords(raw, boxName){
  const m = normWords(raw);
  const words = m ? m.split(' ') : [];
  if(words.length !== 12) return { err: 'The '+boxName+' has '+words.length+(words.length===1?' word':' words')+', it needs exactly 12.' };
  for(let i=0;i<12;i++){ if(wordlist.indexOf(words[i]) < 0) return { err: 'In the '+boxName+', word '+(i+1)+' is not on the standard word list. Check it against the card.' }; }
  try{ halfScalar(m); }catch(e){ return { err: 'The '+boxName+' does not pass its built-in check. Compare it against the card word by word.' }; }
  return { m };
}

// Remove any produced secret from the DOM. Called before every attempt, on error, on card/word change, on Done, on pagehide.
function clearResult(){ $('outAddr').textContent = ''; $('outWif').textContent = ''; $('resultBox').classList.add('hide'); }
function clearSetup(){
  $('outWords').textContent = ''; $('outSetupAddr').textContent = ''; $('verifyWords').value = '';
  $('verifyOut').textContent = ''; $('genOut').textContent = '';
  const hw = $('haveWords'); if(hw) hw.value = '';
  const ho = $('haveOut'); if(ho) ho.textContent = '';
  $('setupResult').classList.add('hide');
  $('addrBox').classList.add('hide');
}
// numbered two-column grid matching the card's printed lines (1-6 left, 7-12 right)
function wordGrid(m){
  const w = m.split(' ');
  let out = '';
  for(let i=0;i<6;i++){ out += ' '+String(i+1).padStart(2)+'. '+w[i].padEnd(10)+String(i+7).padStart(2)+'. '+w[i+6]+'\n'; }
  return out;
}


// This tool is the last-resort path, often used years later from a saved copy, so it must prove itself
// against the published reference card before it will produce a key. It previously had no self-test at all.
function frozenVectorGate(){
  const v = verifyFrozenVector();
  if(v.ok) return true;
  try{
    ['p1','p2','revealBtn','genBtn','verifyWords','verifyBtn','haveWords','haveCheckBtn','haveWordsBtn','modeSetup','modeOpen']
      .forEach(id => { const e = $(id); if(e) e.disabled = true; });
    const box = document.createElement('div');
    box.className = 'warn';
    box.textContent = 'This copy of the tool is not safe to use. It failed its built-in check against the published '
      + 'reference card, so it would work out the wrong key. Do not enter any words. Get a fresh copy, check its '
      + 'SHA-256 against the published value, and try again. Your card and your bitcoin are unaffected. [CORE-01]';
    const wrap = document.querySelector('.wrap'); if(wrap) wrap.insertBefore(box, wrap.firstChild);
  }catch(e){}
  return false;
}

function init(){
  if(!frozenVectorGate()) return;
  const isMain = NET.hrp === 'bc';
  document.title = 'Bitcard offline key tool (' + NET.label + ')';
  const nb = $('netbadge');
  if(nb){ nb.textContent = isMain ? 'Real bitcoin · mainnet' : 'TESTNET · practice';
    nb.style.cssText = 'font-size:11px;font-weight:800;border-radius:999px;padding:3px 10px;white-space:nowrap;' + (isMain ? 'background:#E07B12;color:#fff' : 'background:#eee;color:#555'); }

  // The "trust no website" promise only holds when this file runs from a SAVED copy (file://). Served live over the
  // web, a compromised host could ship a modified page, so we REFUSE secret entry and require download-then-open-offline.
  // Both modes make or reveal secrets, so BOTH are gated: word entry and word generation stay off unless run from a saved file.
  const LIVE = (location.protocol !== 'file:');
  if(LIVE){
    ['p1','p2','revealBtn','genBtn','verifyWords','verifyBtn','haveWords','haveCheckBtn','haveWordsBtn'].forEach(id => { const el=$(id); if(el) el.disabled = true; });
    const rb = $('revealBtn'); if(rb) rb.textContent = 'Save this page, then open it offline to use it';
    const gb = $('genBtn'); if(gb) gb.textContent = 'Save this page, then open it offline to use it';
    const g = $('liveGate'); if(g) g.classList.remove('hide');
  }

  // mode chooser: the card code box stays visible for both
  const showMode = which => {
    $('setupCard').classList.toggle('hide', which !== 'setup');
    $('openCard').classList.toggle('hide', which !== 'open');
    $('haveWordsCard').classList.toggle('hide', which !== 'have');
    // leaving setup entirely (not just stepping into the check-existing route) drops any generated words
    if(which !== 'setup' && which !== 'have'){ resetSetupState(); clearSetup(); }
    if(which !== 'open') clearResult();
    $('modeSetup').classList.toggle('hide', which !== null);
    $('modeOpen').classList.toggle('hide', which !== null);
    try{ window.scrollTo(0,0); }catch(e){}
  };
  // v1 records carry no checksum, so a mistyped code can decode to a valid card holding a different key.
  // For cards we made we know the real key, so a corrupted code is caught here rather than at funding time.
  const CARD06 = 'This code is not quite right. It looks like a card code, but it does not match the card we made with that number, so one character is probably wrong. Do not send any bitcoin using it. Scan the QR on the back of the card instead of typing the code. [CARD-06]';
  const requireCard = () => {
    try{
      const c = parseAndVerifyCard(normCardInput($('cardUri').value));
      if(knownCardStatus(c.P1hex, c.serial, c.version) === 'mismatch'){
        $('cardStatus').textContent = CARD06;
        try{ $('cardUri').scrollIntoView({behavior:'smooth', block:'center'}); }catch(err){}
        return null;
      }
      return c;
    }
    catch(e){
      $('cardStatus').textContent = 'First paste the card code above, or the whole link from scanning the card QR.';
      try{ $('cardUri').scrollIntoView({behavior:'smooth', block:'center'}); }catch(err){}
      return null;
    }
  };
  const requireFundingCard = () => {
    const c = requireCard();
    if(!c) return null;
    if(c.version === 1 && knownCardStatus(c.P1hex, c.serial, c.version) !== 'ok'){
      $('cardStatus').textContent = 'This legacy card code is not an exact issued Bitcard record, so this tool will not create a funding address from it. Re-scan the QR on the card. Opening with both word halves remains available. [CARD-08]';
      return null;
    }
    return c;
  };
  $('modeSetup').onclick = ()=>{ if(requireFundingCard()) showMode('setup'); };
  $('modeOpen').onclick  = ()=>{ if(requireCard()) showMode('open'); };
  $('setupBack').onclick = ()=> showMode(null);
  $('openBack').onclick  = ()=> showMode(null);

  try{ const h = (location.hash||'').replace(/^#/,'').trim(); if(h){ $('cardUri').value = h.startsWith('bitcard:') ? h : ('bitcard:'+h); } }catch(e){}
  function refreshCardStatus(){
    const val = $('cardUri').value.trim();
    if(!val){ $('cardStatus').textContent = ''; return; }
    try{
      const c = parseAndVerifyCard(normCardInput(val));
      const known = knownCardStatus(c.P1hex, c.serial, c.version);
      const fundingOK = c.version !== 1 || known === 'ok';
      $('cardStatus').textContent = known === 'mismatch' ? CARD06 : fundingOK
        ? '✓ card loaded (No. '+c.serial+')'
        : 'This legacy card code is not an exact issued Bitcard record. Do not add bitcoin using it. Re-scan the QR on the card. Opening with both word halves remains available. [CARD-08]';
      const setupButton = $('modeSetup'); if(setupButton) setupButton.disabled = !fundingOK;
    }
    catch(e){ $('cardStatus').textContent = /checksum/.test(e.message)
      ? 'One character of this code is mistyped: the code carries its own check digits and they do not add up. Compare it with the card character by character. [CARD-07]'
      : /multiple cards/.test(e.message)
      ? 'More than one card link was pasted, so we cannot tell which card you are holding. Clear the box and paste only the link for the card in your hand.'
      : 'That code is not complete yet. Paste the whole card code, or the whole link from scanning the QR.'; }
  }
  // a different card must never leave the previous card's words, address, or key on screen
  // a different card must wipe the generated words too, not just the display: verifying against a stale
  // card record would show a deposit address belonging to the previous card
  function clearCardBoundSecrets(){
    clearResult(); clearSetup();
    for(const id of ['p1','p2']){ const el=$(id); if(el) el.value=''; }
    for(const id of ['wc1','wc2','keyOut']){ const el=$(id); if(el) el.textContent=''; }
  }
  $('cardUri').addEventListener('input', ()=>{ resetSetupState(); clearCardBoundSecrets(); refreshCardStatus(); showMode(null); });
  // A saved page can have its fragment changed without a reload (scanning a second card into the same tab).
  // Without this the tool would keep showing the FIRST card's generated words while the fragment says another
  // card, and an operator could write those words onto the wrong physical card. Same fail-closed reset the
  // hosted app performs.
  window.addEventListener('hashchange', ()=>{
    try{ const h=(location.hash||'').replace(/^#/,'').trim(); if(h){ $('cardUri').value = h.startsWith('bitcard:')?h:('bitcard:'+h); } }catch(e){}
    resetSetupState(); clearCardBoundSecrets(); refreshCardStatus(); showMode(null);
  });
  refreshCardStatus();

  // ---------- SETUP MODE (no website, no sealed half needed) ----------
  // Safety model, matching the hosted give flow:
  //   1. Generating words is gated on the operator confirming the card's write lines are physically BLANK.
  //      This gate cannot live in memory alone: a reload wipes state, so it is asked on EVERY first generation.
  //   2. The deposit address is NOT shown until the buyer re-types the words correctly. Funding an address
  //      whose words were miscopied is unrecoverable, so verification is mandatory, not advisory.
  //   3. Once verified, generation is locked for the session: new words would abandon a card that may be funded.
  let setupState = null;         // { p1hex, mnemonic, addr }
  let setupVerified = false;     // set when the re-typed words reproduce the address; locks regeneration
  const resetSetupState = ()=>{ setupState = null; setupVerified = false; };

  $('genBtn').onclick = ()=>{
    if(LIVE){ log('genOut','This page is running from a website, so it will not make card words here. Save the file and open it offline.','bad'); return; }   // fail closed in code, not just via the disabled attribute
    const card = requireFundingCard(); if(!card) return;
    if(setupVerified){
      log('genOut','These words are checked and belong to this card now. Making new ones is disabled so bitcoin cannot be sent to words that were thrown away. To set up a different, unused card, change the card code above.','bad');
      return;
    }
    // physical-state gate: asked on the first generation of EVERY session, because a reload forgets everything
    // A cancelled dialog used to return in silence. Some in-app browsers suppress confirm() entirely and it
    // then reports Cancel without ever showing anything, so the button looked broken with no way to tell why.
    // Refusing is the safe answer either way, so keep refusing, but always say so.
    if(!setupState && !confirm('Quick check: are the numbered word lines on this card completely BLANK?\n\nIf words are already written there, press Cancel. That card was set up before, and making new words for it can lose bitcoin. Use "I already wrote words on this card" instead.')){
      log('genOut','No new words were made. If this card already has words written on it, keep them and choose "I already wrote words on this card". If the lines really are blank and you did not see a question just now, your browser is blocking pop-up questions: open this file in Safari or Chrome directly.','bad');
      return;
    }
    if(setupState && !confirm('Make a NEW set of 12 words?\n\nOnly do this if you have NOT written the current words on the card and have NOT sent any bitcoin. The old words and their deposit address cannot be recovered.')){
      log('genOut','Kept the words already shown. Nothing changed.','');
      return;
    }
    clearSetup();
    try{
      const m = newMnemonic();
      const addr = setupAddress(card.P1hex, halfScalar(m));   // card public half + fresh half, all on this device
      setupState = { p1hex: card.P1hex, mnemonic: m, addr };
      setupVerified = false;
      $('outWords').textContent = wordGrid(m);
      $('setupResult').classList.remove('hide');
      $('genOut').textContent = 'Card No. ' + card.serial + ': 12 words made on this device. Nothing was sent anywhere. Write them on the card, then re-type them below to see the deposit address.';
    }catch(e){ log('genOut','Could not set up this card: '+e.message,'bad'); }
  };

  $('verifyBtn').onclick = ()=>{
    if(LIVE){ log('verifyOut','This page is running from a website. Save the file and open it offline.','bad'); return; }
    if(!setupState){ log('verifyOut','Make the 12 words first.','bad'); return; }
    const card = requireCard(); if(!card) return;
    if(card.P1hex !== setupState.p1hex){   // the card box changed after generating: never verify against a stale card
      log('verifyOut','The card code changed after these words were made. Start again with the card you are holding.','bad');
      resetSetupState(); clearSetup(); return;
    }
    const r = checkWords($('verifyWords').value, 'box'); if(r.err){ log('verifyOut', r.err, 'bad'); return; }
    let ok = false;
    try{ ok = setupAddress(setupState.p1hex, halfScalar(r.m)) === setupState.addr; }catch(e){}
    if(ok){
      setupVerified = true;
      $('verifyWords').value = '';
      log('verifyOut','✓ Your writing matches. The deposit address is below.','ok');
      $('outSetupAddr').textContent = setupState.addr;
      $('addrBox').classList.remove('hide');
    }else{
      $('addrBox').classList.add('hide'); $('outSetupAddr').textContent = '';
      log('verifyOut','✗ Those words do not match the 12 shown above, so the deposit address stays hidden on purpose. Nothing is lost and no bitcoin is at risk yet. Compare what you wrote against the list above, word by word and in order, then try again.','bad');
    }
  };

  // Non-generating route for a card whose words are already written: derives the address, never replaces anything.
  $('haveWordsBtn').onclick = ()=>{ if(requireCard()) showMode('have'); };
  $('haveBack').onclick = ()=> showMode('setup');
  $('haveCheckBtn').onclick = ()=>{
    if(LIVE){ log('haveOut','This page is running from a website. Save the file and open it offline.','bad'); return; }
    const card = requireCard(); if(!card) return;
    const r = checkWords($('haveWords').value, 'box'); if(r.err){ log('haveOut', r.err, 'bad'); return; }
    try{
      const addr = setupAddress(card.P1hex, halfScalar(r.m));
      $('haveOut').textContent = 'Card No. ' + card.serial + ' with those words has this deposit address:\n\n' + addr +
        '\n\nIf that is NOT the address you funded, then one of the words you typed is different from what is written on the card. Nothing has been changed by checking.';
    }catch(e){ log('haveOut','Could not work that out: '+e.message,'bad'); }
  };

  $('setupDone').onclick = ()=>{ resetSetupState(); clearSetup(); };

  // count exactly the way validation parses (normWords), so a comma separated list does not read "1 of 12 words"
  function wireCounter(inp,out){ const el=$(inp),o=$(out); el.addEventListener('input',()=>{ const t=normWords(el.value); const n=t?t.split(' ').length:0; o.textContent=n?(n+' of 12 words'):''; $('keyOut').textContent=''; clearResult(); }); }
  wireCounter('p2','wc2'); wireCounter('p1','wc1');

  $('revealBtn').onclick = ()=>{
    if(LIVE){ log('keyOut','This page is running from a website, so it will not rebuild your key here. Save the file and open it offline.','bad'); return; }   // fail closed in code, not just via the disabled attribute
    clearResult(); $('keyOut').textContent = '';   // never let a previous key survive a new or failed attempt
    let card;
    try{ card = parseAndVerifyCard(normCardInput($('cardUri').value)); }
    catch(e){ log('keyOut','First paste the card code, or the whole link from scanning the QR on the back of the card.','bad'); return; }
    // validated in on-screen order, which matches the card's top-to-bottom layout: sealed half first
    const r1 = checkWords($('p1').value, 'scratch-panel box'); if(r1.err){ log('keyOut', r1.err, 'bad'); return; }
    const r2 = checkWords($('p2').value, 'handwritten box'); if(r2.err){ log('keyOut', r2.err, 'bad'); return; }
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
  window.addEventListener('pagehide', ()=>{ try{ resetSetupState(); clearResult(); clearSetup(); $('p1').value=''; $('p2').value=''; }catch(e){} });

  showMode(null);
  showBuildHash();
  // "saved-file mode" is the honest label: file:// proves this is a saved copy, NOT that networking is off.
  // The real protection is that this bundle contains no network code at all.
  const st = $('status'); if(st) st.textContent = LIVE ? 'download this page and open the saved file to unlock it' : 'ready (saved-file mode, no network code in this page)';
}
init();
