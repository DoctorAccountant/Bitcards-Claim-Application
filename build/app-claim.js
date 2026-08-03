// Bitcard PUBLIC claim app (spec v0.4). Consumer-facing guided flows; copy shaped by a three-critic UX debate.
// Contains NO issuer key and NO card creation. The crypto is unchanged from the verified core;
// this file is the UI layer that calls it. All the sweep-security checks (§7) are preserved.
// Copy rules: no em dashes anywhere; JS strings avoid apostrophes (use full words); HTML may use contractions.
import { $, log, bip39, wordlist, btc, BTCNET, NET, hexlib, b64u,
  parseAndVerifyCard, normCardInput, buildRecord, halfScalar, pubOfScalar, setupAddress, combine, bigToBytes32, showBuildHash,
  estVbytes, MAX_FEERATE, bumpEligible, splitConfirmed } from './core.js';
import { getUtxos, feeRate, broadcastTx } from './net.js';   // network layer (online app only)
import { ENDPOINTS } from './endpoints.js';                  // node URLs (online app only); the offline tool never imports this

window.addEventListener('error', e => { const s=document.getElementById('status'); if(s) s.textContent='BUNDLE ERROR: '+(e.message||(e.error&&e.error.message)||e); });

function show(id){ ['chooser','giveFlow','claimFlow','balFlow'].forEach(x=> $(x).classList.toggle('hide', x!==id)); try{ window.scrollTo(0,0); }catch(e){} }

// word-input helpers: normalize (halfScalar trims/lowers but does not collapse inner whitespace)
// and validate per field so errors name the box and the problem instead of one catch-all.
function normWords(s){ return (s||'').trim().toLowerCase().replace(/\s+/g,' '); }
function checkWords(raw, boxName){
  const m = normWords(raw);
  const words = m ? m.split(' ') : [];
  if(words.length !== 12) return { err: 'The '+boxName+' has '+words.length+(words.length===1?' word':' words')+', it needs exactly 12. Type them in order with a space between each one.' };
  for(let i=0;i<12;i++){ if(wordlist.indexOf(words[i]) < 0) return { err: 'Word '+(i+1)+' in the '+boxName+' ("'+words[i]+'") is not recognized. That is almost always a typo or a misread letter, so nothing is lost. Look at word '+(i+1)+' on the card again and retype it.' }; }
  try{ halfScalar(m); }catch(e){ return { err: 'The phrase in the '+boxName+' is not a valid 12-word set. Usually one word is misspelled, or two words are in the wrong order. Your bitcoin is safe on the card and nothing has been sent. Check their spelling and order against the card, one word at a time.' }; }
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

function loadCard(){ return parseAndVerifyCard(normCardInput($('cardUri').value)); }
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
    $('showOut').textContent = 'We could not reach the bitcoin network to check the balance. Nothing was sent and nothing is wrong with your words. This page still has your card open: check your internet connection, then tap Try again, you do not need to retype anything. [NET-01]';
    $('retryBal').classList.remove('hide');
    return;
  }
  const total = utxos.reduce((s,u)=>s+u.value,0);
  if(total <= 0){
    $('showOut').textContent = 'No bitcoin is showing on this card right now. Nothing was moved by this check. First, compare both sets of words with the card one word at a time, then tap Try again. If the words are correct, the payment may have been sent very recently, may not have been sent yet, or the card may have been claimed before. [CARD-04]';
    $('retryBal').classList.remove('hide');
    $('sendSection').classList.add('hide');
    return;
  }
  $('showOut').textContent = '';
  const sp = document.createElement('span'); sp.className = 'ok';
  const pend = splitConfirmed(utxos).pend;
  sp.textContent = '✓ This card holds '+sats(total)+' satoshis ("sats"), tiny units of bitcoin, like cents to a dollar. The exact amount is '+btcStr(total)+' BTC.'
    + (pend > 0 ? ' Note: '+sats(pend)+' sats of this only just arrived and the bitcoin network has not confirmed it yet. Until it does, that part can still fall through, and if you send now your payment has to wait behind it. Wait about an hour and check again. The bitcoin is not going anywhere.' : '');
  $('showOut').appendChild(sp);
  $('sendSection').classList.remove('hide');
}

// ---- card-binding + reset (prevents card A state being used to fund/spend card B) ----
// must normalize the same way loadCard does: otherwise a pasted full link parses as null here and
// cardChanged() reports a card swap that never happened, wiping the flow state mid-claim
function cardKey(){ try{ return parseAndVerifyCard(normCardInput($('cardUri').value)).P1hex; }catch(e){ return null; } }
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
  feecap:      'The fee for this payment is above our safety limit right now. Nothing was sent, the bitcoin is still on the card. Try again in a few hours [FEE-01], or use the offline tool at bitcards.xyz/offline.html and sweep with your own wallet, where you choose the fee yourself.',
  feehalf:     'Right now the network fee would eat more than half of what is on this card, so we stopped. Nothing was sent, the bitcoin is still on the card. Fees change hour to hour [FEE-02]: try again later, or use the offline tool at bitcards.xyz/offline.html and sweep with your own wallet, where you choose the fee yourself.',
  destmismatch:'Safety check failed, the address did not match. Nothing was sent. Re-check your wallet address.'
};

function init(){
  // network banner from config; brand orange for real money, red stays reserved for errors
  const isMain = NET.hrp === 'bc';
  document.title = 'Bitcard ' + NET.label;
  const nb = $('netbadge');
  // On mainnet the badge said nothing a customer asked, and hinting "real" invites "as opposed to?".
  // It only earns its place as a warning, so it appears for practice builds only.
  if(nb){ nb.textContent = isMain ? '' : 'PRACTICE ONLY, not real bitcoin';
    if(!isMain) nb.style.cssText = 'font-size:11px;font-weight:700;border-radius:999px;padding:5px 11px;white-space:nowrap;background:#B3341F;color:#fff'; }

  // scan-and-go: a scanned card arrives in the URL fragment (never sent to any server)
  try{ const h = (location.hash||'').replace(/^#/,'').trim(); if(h){ $('cardUri').value = h.startsWith('bitcard:') ? h : ('bitcard:'+h); } }catch(e){}

  // presentation only: a header chip so the loaded card stays visible after the chooser is hidden
  function setChip(text){
    const el = $('cardChip'); if(!el) return;
    el.textContent = text || '';
    el.classList.toggle('hide', !text);
  }
  // route buttons stay disabled until a real card is loaded, so tapping one can never just produce an error
  function setRoutesEnabled(on){
    ['pathGive','pathClaim','pathBal'].forEach(id => { const el = $(id); if(el) el.disabled = !on; });
  }
  // Once a card is loaded the serial in the header is the confirmation, so the paste box collapses
  // to a quiet link. Someone who scanned never needed the box; someone without a card still gets it.
  function showCardBox(on){
    const box = $('cardBox'), link = $('changeCard');
    if(box) box.classList.toggle('hide', !on);
    if(link) link.classList.toggle('hide', on);
  }
  function refreshCardStatus(){
    const val = $('cardUri').value.trim();
    if(!val){ $('cardStatus').textContent = ''; setChip(''); setRoutesEnabled(false); showCardBox(true); return; }
    try{
      const c = loadCard();
      $('cardStatus').textContent = '✓ card loaded (No. '+c.serial+')'; setChip('No. '+c.serial); setRoutesEnabled(true);
      showCardBox(false);
    }catch(e){
      showCardBox(true);
      // distinguish "you are part way through pasting" from "this is not a card code at all"
      const partial = /^(bitcard:)?[A-Za-z0-9_-]*$/.test(val) && val.replace(/^bitcard:/,'').length < 55;
      $('cardStatus').textContent = partial
        ? 'That code is not complete yet. Paste the whole code, or scan the QR on the back of the card with your phone camera.'
        : 'This does not look like a Bitcard code. Scan the QR on the back of the card with your phone camera, or paste the complete Bitcard link.';
      setChip(''); setRoutesEnabled(false);
    }
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
  $('changeCard').onclick = ()=>{ showCardBox(true); const el=$('cardUri'); if(el){ el.focus(); el.select(); } };
  // Back from GIVE keeps the generated words on purpose: they may already be written on a physical card,
  // and silently discarding them would strand any bitcoin later sent to that card. The button label says so.
  $('giveBack').onclick = ()=> show('chooser');
  // Back from CLAIM and BALANCE really does start over: nothing is written down yet, and leaving typed
  // secret words sitting in the boxes is both confusing and a privacy leak on a shared phone.
  $('claimBack').onclick = ()=>{
    claimState = null; lastRawTx = null; lastTxId = null; lastReviewedDest = null; lastUtxos = null; lastRate = null;
    ['claimP1','claimP2','dest'].forEach(id => { const el=$(id); if(el) el.value=''; });
    ['wc1','wc2','showOut','claimOut','bcastOut','bumpOut','destOut'].forEach(id => { const el=$(id); if(el) el.textContent=''; });
    ['sendSection','confirmRow','bcastBtn','bumpBtn','retryBal'].forEach(id => { const el=$(id); if(el) el.classList.add('hide'); });
    const dc = $('destConfirm'); if(dc) dc.checked = false;
    show('chooser');
  };
  $('balBack').onclick = ()=>{
    const bw = $('balWords'); if(bw) bw.value = '';
    const bo = $('balFlowOut'); if(bo) bo.textContent = '';
    show('chooser');
  };

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
      // same word-by-word diagnosis the claim flow gives, instead of a single vague catch-all
      const chk = checkWords($('verifyWords').value, 'box'); if(chk.err){ log('verifyOut', chk.err, 'bad'); return; }
      const ok = setupAddress(setup.p1, halfScalar(chk.m)) === setup.addr;
      if(ok){
        setupLocked = true;   // audit #6: from here, regeneration is disabled outright (see setupBtn)
        log('verifyOut','✓ The words match. You can add bitcoin now.','ok');
        $('fundOut').textContent = 'Send bitcoin to this address:\n\n  '+setup.addr;
        $('fundBox').classList.remove('hide');
        $('verifyWords').value = '';   // audit #11: do not keep the half on screen after it has been checked
        $('setupOut').textContent = '✓ Your 12 words are written on the card and verified. They were removed from this screen for privacy. Keep the card safe.';   // audit #11: the full word grid must not linger on screen
      }else{
        log('verifyOut','These do not match the 12 words shown above. Nothing is broken and no bitcoin is at risk yet. Check two things: that you typed them in the same order, and that what you wrote on the card really is what is shown above. If the card is what is wrong, fix the card. Do not add any bitcoin until this says the words match.','bad');
        $('fundBox').classList.add('hide');
      }
    }catch(e){ log('verifyOut','That is not 12 valid words yet. Type all 12, in order, with a space between each one.','bad'); }
  };

  $('arriveBtn').onclick = ()=> run('arriveBtn', async ()=>{
    if(!setup.addr){ log('arriveOut','Do Steps 1 and 2 first.','bad'); return; }
    if(cardChanged()){ resetFlowState(); log('arriveOut','The card changed. Please start again from Step 1.','bad'); return; }
    log('arriveOut','Checking...');
    try{
      const utxos = (await getUtxos(setup.addr)).utxos;
      const { conf, pend } = splitConfirmed(utxos);
      // "ready to give" is reserved for CONFIRMED money: a pending payment can in principle still fall through,
      // and a sealed, gifted card must never be backed by funds that never landed.
      if(conf > 0 && pend === 0) log('arriveOut','✓ This card holds '+sats(conf)+' satoshis ("sats", tiny units of bitcoin), confirmed by the bitcoin network. Seal the words and it is ready to give.','ok');
      else if(conf > 0) log('arriveOut','This card holds '+sats(conf)+' sats confirmed, and '+sats(pend)+' more sats are on the way but not confirmed yet. Wait until everything is confirmed before you seal and give it. Check again in a few minutes.');
      else if(pend > 0) log('arriveOut','Your payment of '+sats(pend)+' sats is on the way: the network has seen it but not confirmed it yet. This usually takes ten minutes to an hour. Do not seal or give the card yet, check again once it is confirmed.');
      else log('arriveOut','Nothing has arrived yet. Payments usually show within the hour, check again soon.');
    }catch(e){ log('arriveOut','Could not reach the network: '+e.message,'bad'); }
  });

  // ---------- CLAIM FLOW ----------
  $('showBtn').onclick = ()=> run('showBtn', async ()=>{
    // boxes are validated in on-screen order, which matches the card's top-to-bottom layout: sealed half first
    const r1 = checkWords($('claimP1').value, 'scratch-panel box');
    if(r1.err){ log('showOut', r1.err, 'bad'); return; }
    const r2 = checkWords($('claimP2').value, 'handwritten box');
    if(r2.err){ log('showOut', r2.err, 'bad'); return; }
    let card;
    try{ card = loadCard(); }
    catch(e){ log('showOut','This card code is not valid. Re-scan the QR on the back of the card, then try again. [CARD-01]','bad'); return; }   // audit: fail closed, never skip the pairing check
    // the QR commits the hidden half: catch a mispaired or misread panel deterministically
    if(hexlib.encode(pubOfScalar(halfScalar(r1.m))) !== card.P1hex){
      // before blaming the card, check the commonest human error: the two sets typed into the wrong boxes.
      // If the SECOND box reproduces the card's key, they are simply swapped, and we can say so exactly.
      let swapped = false;
      try{ swapped = hexlib.encode(pubOfScalar(halfScalar(r2.m))) === card.P1hex; }catch(e){}
      if(swapped){
        log('showOut','It looks like the two sets of words are in the wrong boxes. The printed words from under the scratch panel go in the FIRST box, and the handwritten words go in the SECOND box. Swap them and try again. [CARD-03]','bad');
      }else{
        log('showOut','The words from under the scratch panel do not match this card. Re-check the scratched-off words one at a time, and make sure the card code above belongs to the card you are holding. [CARD-02]','bad');
      }
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
    $('destOut').textContent = 'You need somewhere of your own to keep the bitcoin. Two options. If you already use an exchange or an app that holds bitcoin, open it, find Receive, and copy the address. Otherwise install a free bitcoin wallet app, which takes about five minutes. Use a trusted one: fake bitcoin wallets do exist in app stores, so check the app has a long history and many reviews, and it is worth asking someone you trust which one they use. There is no rush at all: the bitcoin stays safe on this card until you move it, so you can close this page and come back another day.';
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
      'Network fee: '+sats(s.fee)+' sats (this goes to the bitcoin network, not to us. We set it from what the network is charging right now and lean to the cautious side. Fees are an estimate, not a promise: most payments confirm within an hour, some take longer, and a Speed it up button appears if yours is slow)\n'+
      'You receive: '+sats(s.send)+' sats ('+btcStr(s.send)+' BTC)\n\n'+
      'Going to:\n  '+s.txDest+'\n\n'+
      'Bitcoin payments cannot be undone, by us or by anyone. Check the address now: open your wallet app next to this page and make sure the first four characters and the last four characters match what your wallet shows. Then tick the box.';
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
      // 'pending' (neutral), not 'bad': the payment DID go through, we just could not double-check it.
      // Red here reads as failure and scares people into thinking their money is lost.
      const bh = document.createElement('span'); bh.className = r.independent ? 'ok' : 'pending';
      if(r.independent){   // host-aware: the accepting node alone can never vouch for its own broadcast
        bh.textContent = '✓ Sent. Your payment is on its way. It should show in your wallet as pending within a few minutes, and it is only final once your wallet marks it confirmed, usually within the hour. Keep the card and both sets of words until you see it confirmed, not just pending. After that the card is spent for good: never send bitcoin to this card again, because anyone who has seen the opened card can take it.';
      }else{
        bh.textContent = 'Your payment went through and is on its way. We could not double-check it with a second server, so we will not promise until you see it. Keep the card and both sets of words for now, and check your wallet app in about ten minutes. If nothing has arrived after an hour, come back to this page and send again. That is safe: the same bitcoin cannot be sent twice, so a second attempt cannot pay anyone twice.';
      }
      bo.appendChild(bh);
      bo.appendChild(document.createTextNode('\n\nReceipt (transaction id):\n'+r.txid+'\n\n'));
      const a = document.createElement('a'); a.href = ENDPOINTS.txExplorer +r.txid; a.textContent = 'Track the payment'; a.target = '_blank'; a.rel = 'noopener';
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
      const sp = document.createElement('span'); sp.className = r.independent ? 'ok' : 'pending';
      sp.textContent = (r.independent ? '✓ Done. ' : 'Sent a faster version, still confirming. ') + 'We asked the network to move things along by paying a larger fee. New fee '+sats(s.fee)+' sats, you receive '+sats(s.send)+' sats. This is still the same single payment, not a second one, so nothing can be paid twice.';
      bo.appendChild(sp);
      bo.appendChild(document.createTextNode('\n\nNew receipt (transaction id):\n'+s.txid+'\n\n'));
      const a = document.createElement('a'); a.href = ENDPOINTS.txExplorer +s.txid; a.textContent = 'Track the payment'; a.target = '_blank'; a.rel = 'noopener';
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
      const bPend = splitConfirmed(utxos).pend;
      if(total > 0) log('balFlowOut','This card holds '+sats(total)+' satoshis ("sats"), tiny units of bitcoin ('+btcStr(total)+' BTC)'+(bPend > 0 ? ', of which '+sats(bPend)+' sats arrived recently and are still confirming' : '')+'. Keep the panel sealed until you are ready to claim.','ok');
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
