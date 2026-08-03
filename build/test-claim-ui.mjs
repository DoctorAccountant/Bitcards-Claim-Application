// Adversarial UI harness for the CLAIM APP: the artifact that actually moves money.
// The offline tool had a harness; this one did not, so its money-path guards were only ever
// verified by hand. Every assertion here is an invariant that, if broken, loses customer funds.
//
// Drives the REAL built bundle against a minimal DOM with a scripted network.
// Run: node test-claim-ui.mjs app-claim.bundle.js
import fs from 'node:fs';
import * as btc from '@scure/btc-signer';
import { hex } from '@scure/base';

// An honest node echoes back the txid of the transaction it was handed. The app requires that echo to
// match the id it computed locally, so the mock has to actually parse the posted transaction.
const txidOf = rawHex => { try{ return btc.Transaction.fromRaw(hex.decode(rawHex.trim())).id; }catch(e){ return null; } };

const BUNDLE = process.argv[2] || 'app-claim.bundle.js';
const CARD_999 = 'AQABAQOrOxUP6VvN0TIX0jhu801U5qRPbtBVoprrQ1nfUazLJgAAA-c';
const CARD_VEC = 'AQABAQPZAvNfVg4EcMYzE8c2kWjZ198tSb8pX9n7fLEJzO4ElAAAAHs';
const TXID = 'a'.repeat(64);

const IDS = ['netbadge','cardChip','cardBox','cardUri','cardStatus','changeCard','pathGive','pathClaim','pathBal',
  'chooser','giveFlow','giveBack','setupBtn','setupOut','verifyWords','verifyBtn','verifyOut','fundBox','fundOut',
  'arriveBtn','arriveOut','claimFlow','claimBack','claimP1','wc1','claimP2','wc2','showBtn','showOut','retryBal',
  'sendSection','dest','genDest','destOut','reviewBtn','claimOut','confirmRow','destConfirm','bcastBtn','bcastOut',
  'bumpBtn','bumpOut','balFlow','balBack','balWords','balCheckBtn','balFlowOut','buildhash','selftest','status','appbundle'];
const HIDDEN = ['giveFlow','claimFlow','balFlow','fundBox','sendSection','confirmRow','bcastBtn','bumpBtn','retryBal','changeCard','cardChip'];

function makeEl(id){
  const cls = new Set(HIDDEN.includes(id) ? ['hide'] : []);
  return {
    id, value:'', textContent:'', disabled:false, className:'', checked:false, style:{cssText:''}, onclick:null,
    classList:{ add:c=>cls.add(c), remove:c=>cls.delete(c), contains:c=>cls.has(c),
      toggle:(c,on)=>{ if(on===undefined){ cls.has(c)?cls.delete(c):cls.add(c); } else { on?cls.add(c):cls.delete(c); } } },
    _h:{}, addEventListener(ev,fn){ (this._h[ev]=this._h[ev]||[]).push(fn); },
    dispatch(ev){ (this._h[ev]||[]).forEach(fn=>fn({target:this})); },
    appendChild(c){ this.textContent += c.textContent||''; }, scrollIntoView(){}, focus(){}, select(){}
  };
}

// scripted network: utxos, fee, broadcast acceptance and observation are all controllable per test
function boot(net = {}){
  const els = {}; for(const id of IDS) els[id] = makeEl(id);
  const winH = {};
  globalThis.document = { title:'', getElementById:id=>els[id]||null,
    createElement:()=>({className:'',textContent:'',href:'',target:'',rel:'',appendChild(){}}),
    createTextNode:t=>({textContent:t}) };
  globalThis.window = { addEventListener(ev,fn){ (winH[ev]=winH[ev]||[]).push(fn); }, scrollTo(){},
    dispatch(ev){ (winH[ev]||[]).forEach(fn=>fn({})); }, location:{ protocol:'https:', hash:'' } };
  globalThis.location = globalThis.window.location;
  globalThis.confirm = m => (net.onConfirm ? net.onConfirm(m) : true);
  try{ Object.defineProperty(globalThis,'navigator',{value:{clipboard:{writeText(){}}},configurable:true}); }catch(e){}

  const utxos = net.utxos === undefined ? [] : net.utxos;
  globalThis.fetch = async (url, opts) => {
    if(opts && opts.method === 'POST'){
      if(net.rejectPost && net.rejectPost(url)) return { ok:false, status:400, text:async()=>'rejected by this node' };
      const honest = txidOf(opts.body);
      return { ok:true, status:200, text:async()=> (net.broadcastTxid || honest || TXID) };
    }
    if(/\/tx\/[0-9a-f]{64}\/status/.test(url)) return { ok: net.observedBy ? net.observedBy(url) : true, status:200, text:async()=>'{}' };
    if(/fee-estimates/.test(url)) return { ok:true, status:200, json:async()=>({ '2': net.feeRate || 2 }) };
    if(/\/utxo/.test(url)) return { ok:true, status:200, json:async()=>utxos };
    return { ok:true, status:200, json:async()=>({}), text:async()=>'{}' };
  };
  new Function(fs.readFileSync(BUNDLE,'utf8'))();
  return { els, win: globalThis.window };
}

let pass=0, fail=0;
const ok = (n,c,d)=>{ c?pass++:(fail++,console.log('FAIL: '+n+(d!==undefined?'\n      got: '+JSON.stringify(d):''))); };
const tick = ms => new Promise(r=>setTimeout(r,ms||60));
const utxo = (v,conf)=>({ txid:'b'.repeat(64), vout:0, value:v, status:{confirmed:!!conf} });

// ---------------- 1. ROUTE GATING ----------------
{
  const { els } = boot();
  ok('no card: all three routes disabled', els.pathGive.disabled && els.pathClaim.disabled && els.pathBal.disabled);
  els.cardUri.value = 'not a card at all'; els.cardUri.dispatch('input');
  ok('junk card: routes stay disabled', els.pathGive.disabled && els.pathClaim.disabled);
  ok('junk card: message says it is not a Bitcard code', /does not look like a Bitcard code/i.test(els.cardStatus.textContent));
  els.cardUri.value = CARD_999; els.cardUri.dispatch('input');
  ok('valid card: routes enabled', !els.pathGive.disabled && !els.pathClaim.disabled && !els.pathBal.disabled);
  ok('valid card: box collapses', els.cardBox.classList.contains('hide'));
  ok('valid card: change-card link offered', !els.changeCard.classList.contains('hide'));
}

// ---------------- 2. GIVE: address must never precede verification ----------------
{
  const { els } = boot();
  els.cardUri.value = CARD_999; els.cardUri.dispatch('input');
  els.pathGive.onclick();
  els.setupBtn.onclick();
  await tick();
  const grid = els.setupOut.textContent;
  ok('give: 12 words produced', (grid.match(/\d+\.\s+[a-z]+/g)||[]).length === 12);
  ok('give: funding box hidden before verification', els.fundBox.classList.contains('hide'));
  ok('give: no address text present before verification', !/bc1q/.test(els.fundOut.textContent));

  // wrong re-type must not reveal it
  els.verifyWords.value = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
  els.verifyBtn.onclick(); await tick();
  ok('give: wrong re-type keeps funding hidden', els.fundBox.classList.contains('hide') && !/bc1q/.test(els.fundOut.textContent));

  // correct re-type reveals
  const words = []; for(let i=1;i<=12;i++){ const m = grid.match(new RegExp('(?:^|\\s)'+i+'\\.\\s+([a-z]+)')); words.push(m[1]); }
  els.verifyWords.value = words.join(' ');
  els.verifyBtn.onclick(); await tick();
  ok('give: correct re-type reveals funding box', !els.fundBox.classList.contains('hide'));
  ok('give: address now shown', /bc1q[0-9a-z]{38}/.test(els.fundOut.textContent));
  ok('give: words cleared from screen after verify', !/\d+\.\s+[a-z]+/.test(els.setupOut.textContent));

  // regeneration is locked once verified
  const addrBefore = els.fundOut.textContent;
  els.setupBtn.onclick(); await tick();
  ok('give: regeneration locked after verification', /disabled/i.test(els.setupOut.textContent));
  ok('give: locked regeneration did not change the address', els.fundOut.textContent === addrBefore);
}

// ---------------- 3. GIVE: unconfirmed funds are never "ready to give" ----------------
{
  const { els } = boot({ utxos:[utxo(50000,false)] });
  els.cardUri.value = CARD_999; els.cardUri.dispatch('input');
  els.pathGive.onclick(); els.setupBtn.onclick(); await tick();
  const grid = els.setupOut.textContent;
  const words=[]; for(let i=1;i<=12;i++){ words.push(grid.match(new RegExp('(?:^|\\s)'+i+'\\.\\s+([a-z]+)'))[1]); }
  els.verifyWords.value = words.join(' '); els.verifyBtn.onclick(); await tick();
  els.arriveBtn.onclick(); await tick(150);
  ok('give: pending funds are NOT called ready to give', !/ready to give/i.test(els.arriveOut.textContent), els.arriveOut.textContent.slice(0,90));
  ok('give: pending funds say do not seal yet', /do not seal/i.test(els.arriveOut.textContent));
}
{
  const { els } = boot({ utxos:[utxo(50000,true)] });
  els.cardUri.value = CARD_999; els.cardUri.dispatch('input');
  els.pathGive.onclick(); els.setupBtn.onclick(); await tick();
  const grid = els.setupOut.textContent;
  const words=[]; for(let i=1;i<=12;i++){ words.push(grid.match(new RegExp('(?:^|\\s)'+i+'\\.\\s+([a-z]+)'))[1]); }
  els.verifyWords.value = words.join(' '); els.verifyBtn.onclick(); await tick();
  els.arriveBtn.onclick(); await tick(150);
  ok('give: confirmed funds ARE called ready to give', /ready to give/i.test(els.arriveOut.textContent));
}

// ---------------- 4. CLAIM: destination edit after Review must invalidate the draft ----------------
const DEST = 'bc1q6h6zqgr7pzgf4e2j86f2v4m60r5p0wqrvtkvyg';
async function claimToReview(net){
  const { els } = boot(net || { utxos:[utxo(200000,true)] });
  els.cardUri.value = CARD_VEC; els.cardUri.dispatch('input');
  els.pathClaim.onclick();
  els.claimP1.value = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
  els.claimP2.value = 'legal winner thank year wave sausage worth useful legal winner thank yellow';
  els.showBtn.onclick(); await tick(150);
  els.dest.value = DEST;
  els.reviewBtn.onclick(); await tick(150);
  return els;
}
{
  const els = await claimToReview();
  ok('claim: balance found and send section shown', !els.sendSection.classList.contains('hide'));
  ok('claim: review produced a plan', /Nothing has been sent yet/i.test(els.claimOut.textContent));
  ok('claim: confirm row revealed after review', !els.confirmRow.classList.contains('hide'));

  // edit destination after review
  els.dest.value = DEST.slice(0,-1) + 'x';
  els.dest.dispatch('input');
  ok('claim: editing destination hides the send button', els.bcastBtn.classList.contains('hide'));
  ok('claim: editing destination hides the confirm row', els.confirmRow.classList.contains('hide'));
  ok('claim: editing destination clears the reviewed plan', els.claimOut.textContent === '');

  // force a broadcast anyway
  els.destConfirm.checked = true;
  els.bcastBtn.onclick(); await tick(150);
  ok('claim: forced send after edit does NOT broadcast', !/Sent\./i.test(els.bcastOut.textContent), els.bcastOut.textContent.slice(0,90));
  ok('claim: forced send tells user to review again', /Review before sending/i.test(els.bcastOut.textContent));
}

// ---------------- 5. CLAIM: broadcast requires independent observation ----------------
{
  // The lying-acceptor scenario: ONE node accepts and vouches for its own broadcast, the other rejects
  // and never sees it. A single self-interested witness must not be reported as a clean success.
  const els = await claimToReview({
    utxos:[utxo(200000,true)],
    rejectPost: url => /mempool\.space/.test(url),
    observedBy: url => /blockstream/.test(url)
  });
  els.destConfirm.checked = true;
  els.bcastBtn.onclick(); await tick(400);
  ok('claim: acceptor-only observation is not reported as confirmed sent',
     !/^\s*.{0,3}Sent\./i.test(els.bcastOut.textContent) || /could not independently confirm/i.test(els.bcastOut.textContent),
     els.bcastOut.textContent.slice(0,110));
}
{
  const els = await claimToReview({ utxos:[utxo(200000,true)] });   // both nodes observe
  els.destConfirm.checked = true;
  els.bcastBtn.onclick(); await tick(400);
  ok('claim: independently observed broadcast is reported as sent', /Sent\./i.test(els.bcastOut.textContent), els.bcastOut.textContent.slice(0,90));
}

// ---------------- 6. STATE: card change mid-flow must not leave usable state ----------------
{
  const els = await claimToReview();
  els.cardUri.value = CARD_999; els.cardUri.dispatch('input');
  ok('state: card change returns to chooser', !els.chooser.classList.contains('hide'));
  ok('state: card change clears typed words', els.claimP1.value === '' && els.claimP2.value === '');
  ok('state: card change clears the reviewed plan', els.claimOut.textContent === '');
  ok('state: card change hides the send section', els.sendSection.classList.contains('hide'));
  els.destConfirm.checked = true;
  els.bcastBtn.onclick(); await tick(150);
  ok('state: send after card change does not broadcast', !/Sent\./i.test(els.bcastOut.textContent));
}
{
  // same attack via the URL fragment rather than the box
  const els = await claimToReview();
  globalThis.location.hash = '#' + CARD_999;
  els; globalThis.window.dispatch('hashchange'); await tick();
  ok('state: hashchange to another card clears typed words', els.claimP1.value === '' && els.claimP2.value === '');
  ok('state: hashchange returns to chooser', !els.chooser.classList.contains('hide'));
}

// ---------------- 7. BACK semantics ----------------
{
  const els = await claimToReview();
  els.claimBack.onclick();
  ok('back(claim): clears both word boxes', els.claimP1.value === '' && els.claimP2.value === '');
  ok('back(claim): clears destination', els.dest.value === '');
  ok('back(claim): hides send section', els.sendSection.classList.contains('hide'));
  ok('back(claim): returns to chooser', !els.chooser.classList.contains('hide'));
}
{
  const { els } = boot();
  els.cardUri.value = CARD_999; els.cardUri.dispatch('input');
  els.pathGive.onclick(); els.setupBtn.onclick(); await tick();
  const grid = els.setupOut.textContent;
  els.giveBack.onclick();
  els.pathGive.onclick();
  ok('back(give): keeps the generated words, as the button promises', els.setupOut.textContent === grid);
}

// ---------------- 8. BALANCE flow leaves no residue ----------------
{
  const { els } = boot({ utxos:[utxo(1234,true)] });
  els.cardUri.value = CARD_VEC; els.cardUri.dispatch('input');
  els.pathBal.onclick();
  els.balWords.value = 'legal winner thank year wave sausage worth useful legal winner thank yellow';
  els.balCheckBtn.onclick(); await tick(150);
  ok('balance: reports a holding', /1,234/.test(els.balFlowOut.textContent), els.balFlowOut.textContent.slice(0,80));
  ok('balance: words cleared from the box', els.balWords.value === '');
  els.balBack.onclick();
  ok('back(balance): clears the result', els.balFlowOut.textContent === '');
}

console.log('\n' + (fail===0 ? 'CLAIM UI OK ('+pass+' passed)' : 'CLAIM UI FAILED ('+fail+' failures, '+pass+' passed)'));
process.exit(fail===0?0:1);
