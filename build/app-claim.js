// Bitcard PUBLIC claim app (spec v0.4). Consumer-facing guided flows; copy shaped by a three-critic UX debate.
// Contains NO issuer key and NO card creation. The crypto is unchanged from the verified core;
// this file is the UI layer that calls it. All the sweep-security checks (§7) are preserved.
// Copy rules: no em dashes anywhere; JS strings avoid apostrophes (use full words); HTML may use contractions.
import { $, log, bip39, wordlist, btc, BTCNET, NET, hexlib, b64u,
  parseAndVerifyCard, buildRecord, halfScalar, pubOfScalar, setupAddress, combine, bigToBytes32, showBuildHash,
  getUtxos, feeRate, estVbytes, MAX_FEERATE, broadcastTx } from './core.js';

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
let claimState = null; // claim flow: reconstructed { d, pub, address } (kept so a network retry needs no retyping)
let lastRawTx = null;

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
  $('cardUri').addEventListener('input', refreshCardStatus);
  refreshCardStatus();

  // navigation (each flow needs the card loaded first; surface the gate message where the user can see it)
  const go = flow => {
    try{ loadCard(); }
    catch(e){
      $('cardStatus').textContent = 'First scan the QR on the back of the card with your phone camera, or paste the code into the box above.';
      try{ $('cardUri').scrollIntoView({behavior:'smooth', block:'center'}); }catch(err){}
      return;
    }
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

  // ---------- GIVE FLOW ----------
  $('setupBtn').onclick = ()=>{
    try{
      const card = loadCard();
      const m2 = bip39.generateMnemonic(wordlist,128);
      const addr = setupAddress(card.P1hex, halfScalar(m2));
      setup = { p1: card.P1hex, addr };
      $('setupOut').textContent =
        'Write these 12 words on the card, matching the numbered "your half" lines:\n\n'+wordGrid(m2)+'\n'+
        'This is your half of the key, it stays with the card. No words = no bitcoin, and there is no backup. Write them with a pen, do not photograph or message them, anyone who sees both halves can take the bitcoin later.\n\n'+
        'If the lines on the card already have handwriting on them, stop: this card was set up before. Go back and choose the claim option.';
      $('verifyOut').textContent = '';
      $('arriveOut').textContent = '';
      $('fundBox').classList.add('hide');
    }catch(e){ log('setupOut','Something went wrong: '+e.message,'bad'); }
  };

  $('verifyBtn').onclick = ()=>{
    try{
      if(!setup.addr){ log('verifyOut','Please do Step 1 first.','bad'); return; }
      const ok = setupAddress(setup.p1, halfScalar(normWords($('verifyWords').value))) === setup.addr;
      if(ok){
        log('verifyOut','✓ The words match. You can add bitcoin now.','ok');
        $('fundOut').textContent = 'Send bitcoin to this address:\n\n  '+setup.addr;
        $('fundBox').classList.remove('hide');
      }else{
        log('verifyOut','✗ These do not match what is on the card. Re-check the 12 words, do NOT add bitcoin until they match.','bad');
        $('fundBox').classList.add('hide');
      }
    }catch(e){ log('verifyOut','That does not look like 12 valid words yet.','bad'); }
  };

  $('arriveBtn').onclick = async ()=>{
    if(!setup.addr){ log('arriveOut','Do Steps 1 and 2 first.','bad'); return; }
    log('arriveOut','Checking...');
    try{
      const utxos = (await getUtxos(setup.addr)).utxos;
      const total = utxos.reduce((s,u)=>s+u.value,0);
      if(total > 0) log('arriveOut','This card now holds '+sats(total)+' sats. Seal the words and it is ready to give.','ok');
      else log('arriveOut','Nothing has arrived yet. Payments usually show within the hour, check again soon.');
    }catch(e){ log('arriveOut','Could not reach the network: '+e.message,'bad'); }
  };

  // ---------- CLAIM FLOW ----------
  $('showBtn').onclick = async ()=>{
    const r2 = checkWords($('claimP2').value, 'top box');
    if(r2.err){ log('showOut', r2.err, 'bad'); return; }
    const r1 = checkWords($('claimP1').value, 'bottom box');
    if(r1.err){ log('showOut', r1.err, 'bad'); return; }
    // the QR commits the hidden half: catch a mispaired or misread panel deterministically
    try{
      const card = loadCard();
      if(hexlib.encode(pubOfScalar(halfScalar(r1.m))) !== card.P1hex){
        log('showOut','The words from under the scratch panel do not match this card. Re-check the bottom box word by word.','bad');
        return;
      }
    }catch(e){}
    try{
      claimState = combine(halfScalar(r1.m), halfScalar(r2.m));
      $('claimP1').value = ''; $('claimP2').value = '';   // privacy: clear the secret words from the inputs
      $('wc1').textContent = ''; $('wc2').textContent = '';
      await checkClaimBalance();
    }catch(e){ log('showOut','Something went wrong: '+e.message,'bad'); }
  };

  $('retryBal').onclick = ()=>{ if(claimState) checkClaimBalance(); };

  $('genDest').onclick = ()=>{
    $('destOut').textContent = 'You need a wallet app first, it is free and takes about five minutes. Install a well known bitcoin wallet from your app store, open it, tap Receive, and copy the address it shows into the box above. No rush: the bitcoin stays on this card until you move it.';
  };

  $('reviewBtn').onclick = async ()=>{
    if(!claimState){ log('claimOut','Please do Step 1 first (enter your words and tap "Show my bitcoin").','bad'); return; }
    const dest = $('dest').value.trim();
    if(!dest){ log('claimOut','Enter your wallet address. If you do not have a wallet app yet, tap the button below the box.','bad'); return; }
    const c = claimState;
    $('confirmRow').classList.add('hide'); $('bcastBtn').classList.add('hide');
    try{
      let utxos; try{ utxos = (await getUtxos(c.address)).utxos; }catch(e){ log('claimOut','Could not reach the network: '+e.message,'bad'); return; }
      const total = utxos.reduce((s,u)=>s+u.value,0);
      const pay = btc.p2wpkh(c.pub, BTCNET);
      const vb = estVbytes(utxos.length);
      let rate = await feeRate(); if(rate > MAX_FEERATE) rate = MAX_FEERATE;
      const fee = Math.max(200, vb*rate), impliedRate = fee/vb, send = total - fee;
      if(impliedRate > MAX_FEERATE){ log('claimOut','The fee for this payment is above our safety limit right now. Nothing was sent, the bitcoin is still on the card. Try again in a few hours.','bad'); return; }
      if(fee > total*0.5){ log('claimOut','Right now the network fee would eat more than half of what is on this card, so we stopped. Nothing was sent, the bitcoin is still on the card. Fees change hour to hour, try again later.','bad'); return; }
      if(send <= 546){ log('claimOut','After the network fee, what would be left is below the tiny minimum the bitcoin network accepts. Nothing was sent, the bitcoin is still on the card. Try again when fees are lower.','bad'); return; }
      const tx = new btc.Transaction();
      for(const u of utxos){ tx.addInput({ txid:u.txid, index:u.vout, sequence:0xfffffffd, witnessUtxo:{ script:pay.script, amount:BigInt(u.value) } }); } // RBF
      tx.addOutputAddress(dest, BigInt(send), BTCNET);
      const priv = bigToBytes32(c.d);
      tx.sign(priv); priv.fill(0);   // zeroize the key bytes after signing
      tx.finalize();
      let txDest = '(unreadable)'; try{ txDest = btc.Address(BTCNET).encode(btc.OutScript.decode(tx.getOutput(0).script)); }catch(e){ txDest = '(decode error)'; }
      if(txDest === dest){
        lastRawTx = hexlib.encode(tx.extract());
        if($('destConfirm')) $('destConfirm').checked = false;
        $('claimOut').textContent =
          'Nothing has been sent yet. Here is the plan:\n\n'+
          'On the card: '+sats(total)+' sats\n'+
          'Network fee: '+sats(fee)+' sats (set automatically from live network traffic so your payment goes through quickly; it pays the bitcoin network, not us)\n'+
          'You receive: '+sats(send)+' sats ('+btcStr(send)+' BTC)\n\n'+
          'Going to:\n  '+txDest+'\n\n'+
          'Bitcoin payments cannot be undone. Check the address, then tick the box.';
        $('confirmRow').classList.remove('hide'); $('bcastBtn').classList.remove('hide');
      }else{
        lastRawTx = null;
        log('claimOut','Safety check failed, the address did not match. Nothing was sent. Re-check your wallet address.','bad');
      }
    }catch(e){ log('claimOut','Something went wrong: '+e.message,'bad'); }
  };

  $('bcastBtn').onclick = async ()=>{
    if(!lastRawTx){ log('bcastOut','Tap "Review before sending" first.','bad'); return; }
    if($('destConfirm') && !$('destConfirm').checked){ log('bcastOut','Please tick the box to confirm the address is correct.','bad'); return; }
    log('bcastOut','Sending...');
    try{
      const r = await broadcastTx(lastRawTx);
      const bo = $('bcastOut'); bo.textContent = '';
      const bh = document.createElement('span'); bh.className = 'ok';
      bh.textContent = '✓ Sent. Your bitcoin is on its way, it usually appears in your wallet within the hour, often within minutes. You can close this page, the payment finishes on its own. This card is now empty, keep it as a keepsake.';
      bo.appendChild(bh);
      bo.appendChild(document.createTextNode('\n\nReceipt (transaction id):\n'+r.txid+'\n\n'));
      const a = document.createElement('a'); a.href = NET.txExplorer + r.txid; a.textContent = 'Track the payment'; a.target = '_blank'; a.rel = 'noopener';
      bo.appendChild(a);
    }catch(e){ log('bcastOut','Could not send ('+e.message+'). Usually this means nothing moved and you can try again in a minute. If you already tapped Send once, check your wallet first, an earlier try may have gone through.','bad'); }
  };

  // ---------- BALANCE FLOW (keeps the seal intact; needs only the handwritten half) ----------
  $('balCheckBtn').onclick = async ()=>{
    try{
      const card = loadCard();
      const r = checkWords($('balWords').value, 'box');
      if(r.err){ log('balFlowOut', r.err, 'bad'); return; }
      const addr = setupAddress(card.P1hex, halfScalar(r.m));
      log('balFlowOut','Checking...');
      const utxos = (await getUtxos(addr)).utxos;
      const total = utxos.reduce((s,u)=>s+u.value,0);
      if(total > 0) log('balFlowOut','This card holds '+sats(total)+' sats ('+btcStr(total)+' BTC). Keep the panel sealed until you are ready to claim.','ok');
      else log('balFlowOut','There is no bitcoin on this card right now. If it was funded in the last hour, the network may still be processing it, check again soon. If the card was claimed before, the bitcoin has already been moved.');
    }catch(e){ log('balFlowOut','Could not check: '+e.message,'bad'); }
  };

  showBuildHash();
  runSelfTest();
  $('status').textContent = 'claim app v0.4 · open standard · no issuer key · runs on your device';
  show('chooser');
}

if(document.readyState !== 'loading') init();
else document.addEventListener('DOMContentLoaded', init);
