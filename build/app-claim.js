// Bitcard PUBLIC claim app (spec v0.4). Consumer-facing guided flows; copy shaped by a three-critic UX debate.
// Contains NO issuer key and NO card creation. The crypto is unchanged from the verified core;
// this file is the UI layer that calls it. All the sweep-security checks (§7) are preserved.
// Copy rules: no em dashes anywhere; JS strings avoid apostrophes (use full words); HTML may use contractions.
import { $, log, bip39, wordlist, btc, BTCNET, NET, hexlib, b64u,
  parseAndVerifyCard, buildRecord, halfScalar, pubOfScalar, setupAddress, combine, bigToBytes32, showBuildHash,
  getUtxos, feeRate, estVbytes, MAX_FEERATE, bumpEligible, broadcastTx } from './core.js';

window.addEventListener('error', e => { const s=document.getElementById('status'); if(s) s.textContent='BUNDLE ERROR: '+(e.message||(e.error&&e.error.message)||e); });

function show(id){ ['chooser','giveFlow','claimFlow','balFlow'].forEach(x=> $(x).classList.toggle('hide', x!==id)); try{ window.scrollTo(0,0); }catch(e){} }

// word-input helpers: normalize (halfScalar trims/lowers but does not collapse inner whitespace)
// and validate per field so errors name the box and the problem instead of one catch-all.
function normWords(s){ return (s||'').trim().toLowerCase().replace(/\s+/g,' '); }
function checkWords(raw, boxName){
  const m = normWords(raw);
  const words = m ? m.split(' ') : [];
  if(words.length !== 12) return { err: 'The '+boxName+' has '+words.length+(words.length===1?' word':' words')+', it needs exactly 12.' };
  for(let i=0;i<12;i++){ if(wordlist.indexOf(words[i]) < 0) return { err: 'In the '+boxName+', word '+(i+1)+' is not on the standard word list. Check it against the card.' }; }
  try{ halfScalar(m); }catch(e){ return { err: 'All the words are on the list, but the '+boxName+' does not pass its built-in check. Compare it against the card word by word.' }; }
  return { m };
}

// hidden self-check (inside "Verify this app"): aggregation + record round-trip + malformed rejection
function runSelfTest(){
  try{
    const d1 = halfScalar(bip39.generateMnemonic(wordlist,128)), d2 = halfScalar(bip39.generateMnemonic(wordlist,128));
    const aggOK = setupAddress(hexlib.encode(pubOfScalar(d1)), d2) === combine(d1, d2).address;
    const P1 = pubOfScalar(d1);
    const uri = 'bitcard:' + b64u.encode(buildRecord(P1, 42));
    let posOK = false; try{ const v = parseAndVerifyCard(uri); posOK = v.P1hex === hexlib.encode(P1) && v.serial === 42; }catch(e){}
    let negOK = false; try{ parseAndVerifyCard(uri.slice(0, uri.length-4)); }catch(e){ negOK = /length|bitcard|version|curve|point|record/i.test(e.message); }
    $('selftest').textContent = 'self-check: aggregation '+aggOK+' · record round-trip '+posOK+' · malformed rejected '+negOK+' → '+((aggOK&&posOK&&negOK)?'PASS':'FAIL');
  }catch(e){ $('selftest').textContent = 'self-check error: '+e.message; }
}

let setup = {};        // give flow: { p1, addr }
let setupLocked = false; // set once Step-2 verify passes; guards destructive Part-2 regeneration (audit #6)
let claimState = null; // claim flow: reconstructed { d, pub, address } (kept so a network retry needs no retyping)
let lastRawTx = null;
let lastTxId = null;   // txid WE computed for lastRawTx; the broadcaster must echo it back (audit #5)
let lastReviewedDest = null; // the destination the signed draft actually pays; broadcast re-checks the box still matches it (audit #4)
let stateCard = null;  // P1hex the current setup/claimState belongs to; a card change invalidates them (audit: card A->B state bleed)
let lastRate = null;   // sat/vB used for the last sweep, so "speed up" can bid strictly higher (RBF)
let lastUtxos = null;  // the exact inputs the reviewed sweep spends; an RBF bump must re-spend THESE (mempool marks them spent)
let busy = false;      // single in-flight guard: blocks double-clicks and concurrent sign/broadcast

function loadCard(){ return parseAndVerifyCard($('cardUri').value); }
function sats(n){ return n.toLocaleString('en-US'); }
function btcStr(n){ return (n/1e8).toFixed(8); }
// numbered two-column layout (1-6 left, 7-12 right) matching the write lines printed on the card
function wordGrid(m){
  const w = m.split(' ');
  let out = '';
  for(let i=0;i<6;i++){ out += ' '+String(i+1).padStart(2)+'. '+w[i].padEnd(10)+String(i+7).padStart(2)+'. '+w[i+6]+'\n'; }
  return out;
}

// balance check for the claim flow; reusable by the Try again button (claimState survives the input clearing)
async function checkClaimBalance(){
  const c = claimState;
  $('retryBal').classList.add('hide');
  $('showOut').textContent = 'Checking the card...';
  let utxos;
  try{ utxos = (await getUtxos(c.address)).utxos; }
  catch(e){
    $('showOut').textContent = 'We could not reach the bitcoin network to check the balance. Nothing was sent and nothing is wrong with your words. This page still has your card open: check your internet connection, then tap Try again, you do not need to retype anything.';
    $('retryBal').classList.remove('hide');
    return;
  }
  const total = utxos.reduce((s,u)=>s+u.value,0);
  if(total <= 0){
    $('showOut').textContent = 'We did not find any bitcoin on this card. If it was sent in the last hour, the network may still be processing it, wait and try again soon. If someone already used these words to claim it, the bitcoin has been moved. If neither fits, compare all 24 words against the card and try once more.';
    $('retryBal').classList.remove('hide');
    $('sendSection').classList.add('hide');
    return;
  }
  $('showOut').textContent = '';
  const sp = document.createElement('span'); sp.className = 'ok';
  sp.textContent = '✓ This card holds '+sats(total)+' sats ('+btcStr(total)+' BTC). Sats are the small unit of bitcoin, like cents to a dollar.';
  $('showOut').appendChild(sp);
  $('sendSection').classList.remove('hide');
}

// ---- card-binding + reset (prevents card A state being used to fund/spend card B) ----
function cardKey(){ try{ return parseAndVerifyCard($('cardUri').value).P1hex; }catch(e){ return null; } }
function resetFlowState(){
  setup = {}; setupLocked = false; claimState = null;
  lastRawTx = null; lastTxId = null; lastReviewedDest = null; stateCard = null; lastRate = null; lastUtxos = null;
  ['setupOut','verifyOut','arriveOut','fundOut','destOut','claimOut','bcastOut','bumpOut','showOut','balFlowOut','wc1','wc2']
    .forEach(id=>{ const e=$(id); if(e) e.textContent=''; });
  ['verifyWords','claimP1','claimP2','dest','balWords']
    .forEach(id=>{ const e=$(id); if(e) e.value=''; });
  ['fundBox','sendSection','confirmRow','bcastBtn','bumpBtn','retryBal']
    .forEach(id=>{ const e=$(id); if(e) e.classList.add('hide'); });
  const dc = $('destConfirm'); if(dc) dc.checked = false;
}
// true if the loaded card no longer matches the card the current state was built for
function cardChanged(){ return stateCard !== null && stateCard !== cardKey(); }

// single in-flight wrapper: disables the button and blocks concurrent handlers (double-click / double-broadcast races)
async function run(btnId, fn){
  if(busy) return;
  busy = true; const b = $(btnId); if(b) b.disabled = true;
  try{ await fn(); }
  finally{ busy = false; if(b) b.disabled = false; }
}

// ---- one place that builds a signed sweep, so Review and "speed up" (RBF) share identical safety checks ----
// minRate lets the RBF bump bid strictly above the previous fee. Throws coded errors the caller maps to copy.
async function buildSweep(c, dest, minRate, utxosOverride){
  const utxos = utxosOverride || (await getUtxos(c.address)).utxos;   // schema-validated + node-agreed in core; a bump re-uses the reviewed set
  const total = utxos.reduce((s,u)=>s+u.value,0);
  if(total <= 0) throw new Error('empty');
  const pay = btc.p2wpkh(c.pub, BTCNET);
  let rate = await feeRate(); if(minRate && rate < minRate) rate = minRate; if(rate > MAX_FEERATE) rate = MAX_FEERATE;
  const estFee = Math.max(200, estVbytes(utxos.length)*rate);
  if(total - estFee <= 546) throw new Error('dust');         // guard before building so the output is never negative
  const sign = feeSats => {
    const tx = new btc.Transaction();
    for(const u of utxos){ tx.addInput({ txid:u.txid, index:u.vout, sequence:0xfffffffd, witnessUtxo:{ script:pay.script, amount:BigInt(u.value) } }); } // RBF
    tx.addOutputAddress(dest, BigInt(total - feeSats), BTCNET);
    const priv = bigToBytes32(c.d); tx.sign(priv); priv.fill(0); tx.finalize();   // zeroize key bytes after signing
    return tx;
  };
  let tx = sign(estFee);                                     // pass 1: measure the real signed size
  const fee = Math.max(200, Math.ceil(tx.vsize * rate));     // pass 2: fee from ACTUAL vsize, not an estimate
  tx = sign(fee);
  const send = total - fee, impliedRate = fee / tx.vsize;
  if(impliedRate > MAX_FEERATE) throw new Error('feecap');
  if(fee > total*0.5) throw new Error('feehalf');
  if(send <= 546) throw new Error('dust');
  let txDest = '(unreadable)'; try{ txDest = btc.Address(BTCNET).encode(btc.OutScript.decode(tx.getOutput(0).script)); }catch(e){ txDest = '(decode error)'; }
  if(txDest !== dest) throw new Error('destmismatch');
  return { rawTx: hexlib.encode(tx.extract()), txid: tx.id, total, fee, send, txDest, rate, utxos };
}
const SWEEP_ERR = {
  empty:       'This card has no bitcoin on it to send. Nothing was sent.',
  dust:        'After the network fee, what would be left is below the tiny minimum the bitcoin network accepts. Nothing was sent, the bitcoin is still on the card. Try again when fees are lower.',
  feecap:      'The fee for this payment is above our safety limit right now. Nothing was sent, the bitcoin is still on the card. Try again in a few hours.',
  feehalf:     'Right now the network fee would eat more than half of what is on this card, so we stopped. Nothing was sent, the bitcoin is still on the card. Fees change hour to hour, try again later.',
  destmismatch:'Safety check failed, the address did not match. Nothing was sent. Re-check your wallet address.'
};

function init(){
  // network banner from config; brand orange for real money, red stays reserved for errors
  const isMain = NET.hrp === 'bc';
  document.title = 'Bitcard ' + NET.label;
  const nb = $('netbadge');
  if(nb){ nb.textContent = isMain ? 'Real bitcoin · mainnet' : 'TESTNET · practice';
    nb.style.cssText = 'font-size:11px;font-weight:800;border-radius:999px;padding:3px 10px;white-space:nowrap;' + (isMain ? 'background:#E07B12;color:#fff' : 'background:#eee;color:#555'); }

  // scan-and-go: a scanned card arrives in the URL fragment (never sent to any server)
  try{ const h = (location.hash||'').replace(/^#/,'').trim(); if(h){ $('cardUri').value = h.startsWith('bitcard:') ? h : ('bitcard:'+h); } }catch(e){}

  function refreshCardStatus(){
    const val = $('cardUri').value.trim();
    if(!val){ $('cardStatus').textContent = ''; return; }
    try{ const c = parseAndVerifyCard(val); $('cardStatus').textContent = '✓ card loaded (No. '+c.serial+')'; }
    catch(e){ $('cardStatus').textContent = 'That code is not complete yet. Scan the QR on the back of the card, or paste the whole code.'; }
  }
  // audit: the card box changing (paste, or a scan into the same open tab) must wipe ALL flow state, so card A can
  // never be funded/spent with card B in hand. A fresh page load already starts clean; this covers same-session swaps.
  $('cardUri').addEventListener('input', ()=>{ resetFlowState(); refreshCardStatus(); show('chooser'); });
  window.addEventListener('hashchange', ()=>{
    try{ const h=(location.hash||'').replace(/^#/,'').trim(); if(h){ $('cardUri').value = h.startsWith('bitcard:')?h:('bitcard:'+h); } }catch(e){}
    resetFlowState(); refreshCardStatus(); show('chooser');
  });
  window.addEventListener('pagehide', resetFlowState);   // audit #11: drop keys/words/drafts when the page is left
  refreshCardStatus();

  // navigation (each flow needs the card loaded first; surface the gate message where the user can see it)
  const go = flow => {
    try{ loadCard(); }
    catch(e){
      $('cardStatus').textContent = 'First scan the QR on the back of the card with your phone camera, or paste the code into the box above.';
      try{ $('cardUri').scrollIntoView({behavior:'smooth', block:'center'}); }catch(err){}
      return;
    }
    if(cardChanged()) resetFlowState();   // belt and suspenders: state that predates the current card is discarded
    show(flow);
  };
  $('pathGive').onclick = ()=> go('giveFlow');
  $('pathClaim').onclick = ()=> go('claimFlow');
  $('pathBal').onclick = ()=> go('balFlow');
  $('giveBack').onclick = ()=> show('chooser');
  $('claimBack').onclick = ()=> show('chooser');
  $('balBack').onclick = ()=> show('chooser');

  // live word counters on the claim inputs; edits clear any stale error
  function wireCounter(inpId, outId){
    const el = $(inpId), o = $(outId);
    el.addEventListener('input', ()=>{
      const t = el.value.trim();
      const n = t ? t.split(/\s+/).length : 0;
      o.textContent = n ? (n + ' of 12 words') : '';
      $('showOut').textContent = '';
      $('retryBal').classList.add('hide');
    });
  }
  wireCounter('claimP2','wc2');
  wireCounter('claimP1','wc1');

  // audit #4: editing the destination must invalidate any already-signed draft so a stale tx can never be broadcast
  $('dest').addEventListener('input', ()=>{
    lastRawTx = null; lastTxId = null; lastReviewedDest = null;
    if($('destConfirm')) $('destConfirm').checked = false;
    $('confirmRow').classList.add('hide');
    $('bcastBtn').classList.add('hide');
    $('claimOut').textContent = '';
    $('bcastOut').textContent = '';
  });

  // ---------- GIVE FLOW ----------
  $('setupBtn').onclick = ()=> run('setupBtn', async ()=>{
    try{
      const card = loadCard();
      // audit #6: never silently overwrite a set that may already be written on a card and funded.
      // Once Step-2 verification has passed, regeneration is disabled OUTRIGHT (no dialog path): the words are
      // presumed written on a physical card and possibly funded. Reload the page to start over with a fresh card.
      if(setupLocked){
        log('setupOut','These words are checked and belong to this card now. Making new ones is disabled so bitcoin cannot be sent to words that were thrown away. If you truly want to start over with an unfunded card, reload this page.','bad');
        return;
      }
      // a reload wipes the in-memory lock above, so the FIRST generation of a session gates on the card's physical
      // state instead: if words are already handwritten, this card was set up before and must not get a new set.
      if(!setup.addr && !confirm('Quick check: are the numbered word lines on the card still BLANK?\n\nIf words are already handwritten there, press Cancel. This card was set up before, making new words for it can lose bitcoin. Use "This card was given to me" instead.')){
        $('setupOut').textContent = '';
        return;
      }
      if(setup.addr){
        const checkFunded = async () => {
          const u = (await getUtxos(setup.addr)).utxos;
          return u.reduce((s,x)=>s+x.value,0);
        };
        $('setupOut').textContent = 'Checking the current words before replacing them...';
        let total = null;
        try{ total = await checkFunded(); }
        catch(e){
          log('setupOut','We could not reach the network to check whether this card already holds bitcoin, so we did not replace the words. Try again in a moment. If you already wrote the current words on a card, keep them, do not make new ones.','bad');
          return;
        }
        if(total > 0){
          log('setupOut','Stop: the words you already have control '+sats(total)+' sats on this card. Making new words would abandon that bitcoin forever. Keep the words already written on the card. To move that bitcoin, go back and choose: This card was given to me.','bad');
          return;
        }
        if(!confirm('Replace the 12 words with a brand new set?\n\nOnly do this if you have NOT written the current words on a card and have NOT sent any bitcoin yet. This cannot be undone.')){
          $('setupOut').textContent = '';
          return;
        }
        // close the check-then-replace race: funds may have arrived while the dialog sat open; fail closed on any doubt
        try{ if(await checkFunded() > 0){ log('setupOut','Stop: bitcoin arrived on these words while you were deciding. Keeping them. To move that bitcoin, go back and choose: This card was given to me.','bad'); return; } }
        catch(e){ log('setupOut','We could not re-check the network, so we did not replace the words. Try again in a moment.','bad'); return; }
      }
      const m2 = bip39.generateMnemonic(wordlist,128);
      const addr = setupAddress(card.P1hex, halfScalar(m2));
      setup = { p1: card.P1hex, addr };
      stateCard = card.P1hex;   // bind this setup to the loaded card (audit: card A->B)
      setupLocked = false;   // fresh set, Step 2 must verify it again
      $('setupOut').textContent =
        'Write these 12 words on the card, matching the numbered "your half" lines:\n\n'+wordGrid(m2)+'\n'+
        'This is your half of the key, it stays with the card. No words = no bitcoin, and there is no backup. Write them with a pen, do not photograph or message them, anyone who sees both halves can take the bitcoin later.\n\n'+
        'If the lines on the card already have handwriting on them, stop: this card was set up before. Go back and choose the claim option.';
      $('verifyOut').textContent = '';
      $('arriveOut').textContent = '';
      $('fundBox').classList.add('hide');
    }catch(e){ log('setupOut','Something went wrong: '+e.message,'bad'); }
  });

  $('verifyBtn').onclick = ()=>{
    try{
      if(!setup.addr){ log('verifyOut','Please do Step 1 first.','bad'); return; }
      if(cardChanged()){ resetFlowState(); log('verifyOut','The card changed. Please start again from Step 1.','bad'); return; }
      const ok = setupAddress(setup.p1, halfScalar(normWords($('verifyWords').value))) === setup.addr;
      if(ok){
        setupLocked = true;   // audit #6: from here, regeneration is disabled outright (see setupBtn)
        log('verifyOut','✓ The words match. You can add bitcoin now.','ok');
        $('fundOut').textContent = 'Send bitcoin to this address:\n\n  '+setup.addr;
        $('fundBox').classList.remove('hide');
        $('verifyWords').value = '';   // audit #11: do not keep the half on screen after it has been checked
        $('setupOut').textContent = '✓ Your 12 words are written on the card and verified. They were cleared from this screen for privacy; the card is now the only copy.';   // audit #11: the full word grid must not linger on screen
      }else{
        log('verifyOut','✗ These do not match what is on the card. Re-check the 12 words, do NOT add bitcoin until they match.','bad');
        $('fundBox').classList.add('hide');
      }
    }catch(e){ log('verifyOut','That does not look like 12 valid words yet.','bad'); }
  };

  $('arriveBtn').onclick = ()=> run('arriveBtn', async ()=>{
    if(!setup.addr){ log('arriveOut','Do Steps 1 and 2 first.','bad'); return; }
    if(cardChanged()){ resetFlowState(); log('arriveOut','The card changed. Please start again from Step 1.','bad'); return; }
    log('arriveOut','Checking...');
    try{
      const utxos = (await getUtxos(setup.addr)).utxos;
      const total = utxos.reduce((s,u)=>s+u.value,0);
      if(total > 0) log('arriveOut','This card now holds '+sats(total)+' sats. Seal the words and it is ready to give.','ok');
      else log('arriveOut','Nothing has arrived yet. Payments usually show within the hour, check again soon.');
    }catch(e){ log('arriveOut','Could not reach the network: '+e.message,'bad'); }
  });

  // ---------- CLAIM FLOW ----------
  $('showBtn').onclick = ()=> run('showBtn', async ()=>{
    const r2 = checkWords($('claimP2').value, 'top box');
    if(r2.err){ log('showOut', r2.err, 'bad'); return; }
    const r1 = checkWords($('claimP1').value, 'bottom box');
    if(r1.err){ log('showOut', r1.err, 'bad'); return; }
    let card;
    try{ card = loadCard(); }
    catch(e){ log('showOut','This card code is not valid. Re-scan the QR on the back of the card, then try again.','bad'); return; }   // audit: fail closed, never skip the pairing check
    // the QR commits the hidden half: catch a mispaired or misread panel deterministically
    if(hexlib.encode(pubOfScalar(halfScalar(r1.m))) !== card.P1hex){
      log('showOut','The words from under the scratch panel do not match this card. Re-check the bottom box word by word.','bad');
      return;
    }
    try{
      claimState = combine(halfScalar(r1.m), halfScalar(r2.m));
      stateCard = card.P1hex;   // bind this claim to the loaded card (audit: card A->B)
      $('claimP1').value = ''; $('claimP2').value = '';   // privacy: clear the secret words from the inputs
      $('wc1').textContent = ''; $('wc2').textContent = '';
      await checkClaimBalance();
    }catch(e){ log('showOut','Something went wrong: '+e.message,'bad'); }
  });

  $('retryBal').onclick = ()=>{ if(claimState) checkClaimBalance(); };

  $('genDest').onclick = ()=>{
    $('destOut').textContent = 'You need a wallet app first, it is free and takes about five minutes. Install a well known bitcoin wallet from your app store, open it, tap Receive, and copy the address it shows into the box above. No rush: the bitcoin stays on this card until you move it.';
  };

  $('reviewBtn').onclick = ()=> run('reviewBtn', async ()=>{
    if(!claimState){ log('claimOut','Please do Step 1 first (enter your words and tap "Show my bitcoin").','bad'); return; }
    if(cardChanged()){ resetFlowState(); log('claimOut','The card changed. Please start again from Step 1.','bad'); return; }
    const dest = $('dest').value.trim();
    if(!dest){ log('claimOut','Enter your wallet address. If you do not have a wallet app yet, tap the button below the box.','bad'); return; }
    $('confirmRow').classList.add('hide'); $('bcastBtn').classList.add('hide'); $('bumpBtn').classList.add('hide');
    let s;
    try{ s = await buildSweep(claimState, dest, 0); }
    catch(e){ log('claimOut', SWEEP_ERR[e.message] || ('Could not reach the network: '+e.message), 'bad'); return; }
    lastRawTx = s.rawTx; lastTxId = s.txid; lastReviewedDest = dest; lastRate = s.rate; lastUtxos = s.utxos;
    if($('destConfirm')) $('destConfirm').checked = false;
    $('claimOut').textContent =
      'Nothing has been sent yet. Here is the plan:\n\n'+
      'On the card: '+sats(s.total)+' sats\n'+
      'Network fee: '+sats(s.fee)+' sats (set automatically from live network traffic so your payment goes through quickly; it pays the bitcoin network, not us)\n'+
      'You receive: '+sats(s.send)+' sats ('+btcStr(s.send)+' BTC)\n\n'+
      'Going to:\n  '+s.txDest+'\n\n'+
      'Bitcoin payments cannot be undone. Check the address, then tick the box.';
    $('confirmRow').classList.remove('hide'); $('bcastBtn').classList.remove('hide');
  });

  $('bcastBtn').onclick = ()=> run('bcastBtn', async ()=>{
    if(!lastRawTx){ log('bcastOut','Tap "Review before sending" first.','bad'); return; }
    if($('destConfirm') && !$('destConfirm').checked){ log('bcastOut','Please tick the box to confirm the address is correct.','bad'); return; }
    if(cardChanged()){ resetFlowState(); log('bcastOut','The card changed. Please start again from Step 1.','bad'); return; }
    // audit #4: the draft is signed to one exact address; if the box no longer matches it, refuse and force a fresh review
    if($('dest').value.trim() !== lastReviewedDest){
      lastRawTx = null; lastTxId = null; lastReviewedDest = null;
      $('confirmRow').classList.add('hide'); $('bcastBtn').classList.add('hide');
      log('bcastOut','The wallet address changed after you reviewed it. Nothing was sent. Tap "Review before sending" again so you confirm the address it will actually go to.','bad');
      return;
    }
    log('bcastOut','Sending...');
    try{
      const r = await broadcastTx(lastRawTx, lastTxId);   // §5: node must echo the txid we computed
      const bo = $('bcastOut'); bo.textContent = '';
      const bh = document.createElement('span'); bh.className = r.independent ? 'ok' : 'bad';
      if(r.independent){   // host-aware: the accepting node alone can never vouch for its own broadcast
        bh.textContent = '✓ Sent. Your bitcoin is on its way, it usually appears in your wallet within the hour, often within minutes. This card is now empty, keep it as a keepsake.';
      }else{
        bh.textContent = 'A server accepted the payment, but we could not independently confirm it landed on the network yet. Do NOT throw the card away. Keep the card and its words, check your wallet in a few minutes, and use the receipt below to look it up. If it does not appear, you can safely try again.';
      }
      bo.appendChild(bh);
      bo.appendChild(document.createTextNode('\n\nReceipt (transaction id):\n'+r.txid+'\n\n'));
      const a = document.createElement('a'); a.href = NET.txExplorer + r.txid; a.textContent = 'Track the payment'; a.target = '_blank'; a.rel = 'noopener';
      bo.appendChild(a);
      // audit #7: leave a way to un-stick a slow payment. claimState is kept for this and cleared on pagehide/reset.
      $('confirmRow').classList.add('hide'); $('bcastBtn').classList.add('hide');
      $('bumpBtn').classList.remove('hide');
    }catch(e){ log('bcastOut','Could not send ('+e.message+'). Usually this means nothing moved and you can try again in a minute. If you already tapped Send once, check your wallet first, an earlier try may have gone through.','bad'); }
  });

  // audit #7: RBF fee-recovery. Re-signs the SAME sweep (same inputs, same destination) at a strictly higher fee and rebroadcasts.
  $('bumpBtn').onclick = ()=> run('bumpBtn', async ()=>{
    if(!claimState || !lastReviewedDest){ log('bumpOut','There is nothing to speed up on this page. If your payment has not arrived, re-enter your words in Step 1.','bad'); return; }
    if(cardChanged()){ resetFlowState(); return; }
    // both bump guards run through bumpEligible (core.js) so the regression tests exercise the exact same decision
    if(!bumpEligible(lastRate, null, null).ok){ log('bumpOut','The fee is already at the safety maximum of this app, so it cannot go higher. The payment should still confirm, it may just take longer. Keep the card and check your wallet later.','bad'); return; }
    log('bumpOut','Rebuilding at a higher fee...');
    const minRate = Math.max(2, Math.ceil((lastRate||2) * 1.5) + 1);   // bid strictly above the last fee
    let s;
    try{ s = await buildSweep(claimState, lastReviewedDest, minRate, lastUtxos); }   // re-spend the SAME inputs (valid RBF replacement)
    catch(e){ log('bumpOut', SWEEP_ERR[e.message] || ('Could not speed it up: '+e.message), 'bad'); return; }
    // a true replacement must differ; identical txid means the fee could not actually rise (e.g. clamped at the cap)
    if(!bumpEligible(lastRate, s.txid, lastTxId).ok){ log('bumpOut','The rebuilt payment came out identical, the fee could not go any higher. Nothing new was sent, the original payment is still on its way.','bad'); return; }
    try{
      const r = await broadcastTx(s.rawTx, s.txid);
      lastRawTx = s.rawTx; lastTxId = s.txid; lastRate = s.rate;
      const bo = $('bumpOut'); bo.textContent = '';
      const sp = document.createElement('span'); sp.className = r.independent ? 'ok' : 'bad';
      sp.textContent = (r.independent ? '✓ Sped up. ' : 'Sent a faster version, still confirming. ') + 'New fee '+sats(s.fee)+' sats, you receive '+sats(s.send)+' sats. This replaces the earlier payment, only one of them can confirm.';
      bo.appendChild(sp);
      bo.appendChild(document.createTextNode('\n\nNew receipt (transaction id):\n'+s.txid+'\n\n'));
      const a = document.createElement('a'); a.href = NET.txExplorer + s.txid; a.textContent = 'Track the payment'; a.target = '_blank'; a.rel = 'noopener';
      bo.appendChild(a);
    }catch(e){ log('bumpOut','Could not send the faster version ('+e.message+'). Your first payment may still confirm on its own, check your wallet.','bad'); }
  });

  // ---------- BALANCE FLOW (keeps the seal intact; needs only the handwritten half) ----------
  $('balCheckBtn').onclick = ()=> run('balCheckBtn', async ()=>{
    try{
      const card = loadCard();
      const r = checkWords($('balWords').value, 'box');
      if(r.err){ log('balFlowOut', r.err, 'bad'); return; }
      const addr = setupAddress(card.P1hex, halfScalar(r.m));
      $('balWords').value = '';   // audit #11: half is no longer needed once the address is derived; do not hold it through the network call
      log('balFlowOut','Checking...');
      const utxos = (await getUtxos(addr)).utxos;
      const total = utxos.reduce((s,u)=>s+u.value,0);
      if(total > 0) log('balFlowOut','This card holds '+sats(total)+' sats ('+btcStr(total)+' BTC). Keep the panel sealed until you are ready to claim.','ok');
      else log('balFlowOut','There is no bitcoin on this card right now. If it was funded in the last hour, the network may still be processing it, check again soon. If the card was claimed before, the bitcoin has already been moved.');
    }catch(e){ log('balFlowOut','Could not check: '+e.message,'bad'); }
  });

  showBuildHash();
  runSelfTest();
  $('status').textContent = 'claim app v0.4 · open standard · no issuer key · runs on your device';
  show('chooser');
}

if(document.readyState !== 'loading') init();
else document.addEventListener('DOMContentLoaded', init);
