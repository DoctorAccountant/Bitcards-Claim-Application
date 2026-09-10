// Adversarial UI harness for the CLAIM APP: the artifact that actually moves money.
// The offline tool had a harness; this one did not, so its money-path guards were only ever
// verified by hand. Every assertion here is an invariant that, if broken, loses customer funds.
//
// Drives the REAL built bundle against a minimal DOM with a scripted network.
// Run: node test-claim-ui.mjs app-claim.bundle.js
import fs from 'node:fs';
import * as btc from '@scure/btc-signer';
import { hex } from '@scure/base';
import { secp256k1 as secp } from '@noble/curves/secp256k1';
import { halfScalar, combine } from './core.js';
let lastRejectReason = null;

// An honest node echoes back the txid of the transaction it was handed. The app requires that echo to
// match the id it computed locally, so the mock has to actually parse the posted transaction.
const txidOf = rawHex => { try{ return btc.Transaction.fromRaw(hex.decode(rawHex.trim())).id; }catch(e){ return null; } };

// A real node also REJECTS a transaction whose signature does not spend the output it claims. Echoing the
// txid alone cannot detect that: segwit computes the txid WITHOUT witness data, so a mangled signature
// leaves the id byte-identical. External review, 2026-08-03, finding 4: one flipped byte in the witness
// public key still produced ALL SUITES PASSED, meaning the gate advertised signing coverage it did not
// have. A node that accepts an unspendable transaction is not a useful stand-in for the network.
// Amounts come from the UTXO set the "chain" holds, exactly as a real node looks them up: the input value
// is committed to by the BIP143 sighash but is NOT carried in the serialized transaction.
function witnessValid(rawHex, expectPubHex, utxos){
  try{
    const tx = btc.Transaction.fromRaw(hex.decode(rawHex.trim()));
    if(tx.inputsLength === 0) return 'no inputs';
    for(let i = 0; i < tx.inputsLength; i++){
      const inp = tx.getInput(i);
      const w = inp.finalScriptWitness;
      if(!w || w.length !== 2) return 'witness is not a 2-item P2WPKH stack';
      const [sigBytes, pubBytes] = w;
      const outpoint = hex.encode(inp.txid) + ':' + inp.index;
      const known = (utxos || []).find(u => u.txid + ':' + u.vout === outpoint);
      if(!known) return 'spends an output the chain does not have: ' + outpoint;
      // THE CHECK THAT MAKES THE REST MEAN ANYTHING: the offered key must hash to the locking script of
      // the output being spent. Without it the mock derives the scriptCode from the transaction's own
      // witness, so a transaction signed with ANY key verifies against itself and passes. A real node
      // takes the locking script from the chain, never from the spender.
      if(!known.scriptPubKey) return 'mock utxo has no scriptPubKey, so the witness cannot be checked against it';
      if(hex.encode(btc.p2wpkh(pubBytes).script) !== known.scriptPubKey)
        return 'witness key does not match the locking script of the output being spent';
      if(expectPubHex && hex.encode(pubBytes) !== expectPubHex) return 'witness pubkey is not the combined card key';
      // BIP143: for a P2WPKH input the scriptCode in the preimage is the P2PKH form
      // (0x1976a914{keyhash}88ac), NOT the witness program itself.
      const scriptCode = btc.p2pkh(pubBytes).script;
      const sighash = tx.preimageWitnessV0(i, scriptCode, sigBytes[sigBytes.length - 1], BigInt(known.value));
      const sig = secp.Signature.fromDER(sigBytes.slice(0, -1));
      if(!secp.verify(sig, sighash, pubBytes)) return 'signature does not verify against the BIP143 sighash';
    }
    return null;
  }catch(e){ return 'witness check threw: ' + e.message; }
}

const BUNDLE = process.argv[2] || 'app-claim.bundle.js';
const CARD_999 = 'AQABAQOrOxUP6VvN0TIX0jhu801U5qRPbtBVoprrQ1nfUazLJgAAA-c';
const CARD_101 = 'AQABAQNeyFBDvBKLzkvd64SOllZZHCuKXg4IsZ9iuQLKISgIOwAAAGU';
const CARD_101_BOUNDARY_MUTATION = 'AQABAQNeyFBDvBKLzkvd64SOllZZHCuKXg4IsZ9iuQLKISgIOBAAAGU';
const CARD_VEC = 'AQABAQPZAvNfVg4EcMYzE8c2kWjZ198tSb8pX9n7fLEJzO4ElAABYAs';
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

  // Read net.utxos on EVERY call rather than snapshotting at boot. A snapshot cannot express the case that
  // matters most here: a payment landing on the card between Review and Send. A test can now mutate the
  // array mid-flow and the app sees it, exactly as it would against a real node.
  globalThis.fetch = async (url, opts) => {
    const utxos = net.utxos === undefined ? [] : net.utxos;
    if(opts && opts.method === 'POST'){
      net.postCount = (net.postCount||0) + 1;
      if(net.beforePost) await net.beforePost(url,opts);
      if(net.rejectPost && net.rejectPost(url)) return { ok:false, status:400, text:async()=>'rejected by this node' };
      // behave like a real node: refuse anything that would not actually spend
      const bad = net.skipWitnessCheck ? null : witnessValid(opts.body, net.expectPub || hex.encode(CARD_PUB), utxos);
      if(bad){ lastRejectReason = bad; return { ok:false, status:400, text:async()=>'non-mandatory-script-verify-flag: '+bad }; }
      const honest = txidOf(opts.body);
      return { ok:true, status:200, text:async()=> (net.broadcastTxid || honest || TXID) };
    }
    if(/\/tx\/[0-9a-f]{64}\/status/.test(url)) return { ok: net.observedBy ? net.observedBy(url) : true, status:200, text:async()=>'{}' };
    if(/fee-estimates/.test(url)) return { ok:true, status:200, json:async()=>({ '2': net.feeRate || 2 }) };
    // Return a fresh copy, as a real node does. Handing back the same array object let the app's stored
    // snapshot alias the live list, so a mid-flow change mutated both and no comparison could ever see it.
    if(/\/utxo/.test(url)){
      if(net.beforeUtxo) await net.beforeUtxo(url,opts);
      return { ok:true, status:200, json:async()=>utxos.map(u=>({ ...u, status:{ ...u.status } })) };
    }
    return { ok:true, status:200, json:async()=>({}), text:async()=>'{}' };
  };
  new Function(fs.readFileSync(BUNDLE,'utf8'))();
  return { els, win: globalThis.window };
}

let pass=0, fail=0;
const ok = (n,c,d)=>{ c?pass++:(fail++,console.log('FAIL: '+n+(d!==undefined?'\n      got: '+JSON.stringify(d):''))); };
const tick = ms => new Promise(r=>setTimeout(r,ms||60));
// The claim tests always open CARD_VEC with these two halves, so the address being spent is known here.
// The mock chain must carry the real locking script for it, exactly as a node would.
const CLAIM_P1 = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const CLAIM_P2 = 'legal winner thank year wave sausage worth useful legal winner thank yellow';
const CARD_PUB = combine(halfScalar(CLAIM_P1), halfScalar(CLAIM_P2)).pub;
const CARD_SPK = hex.encode(btc.p2wpkh(CARD_PUB).script);
const utxo = (v,conf)=>({ txid:'b'.repeat(64), vout:0, value:v, status:{confirmed:!!conf}, scriptPubKey: CARD_SPK });

// ---------------- 1. ROUTE GATING ----------------
{
  const { els } = boot();
  ok('no card: all three routes disabled', els.pathGive.disabled && els.pathClaim.disabled && els.pathBal.disabled);
  els.cardUri.value = 'not a card at all'; els.cardUri.dispatch('input');
  ok('junk card: routes stay disabled', els.pathGive.disabled && els.pathClaim.disabled);
  ok('junk card: message says it is not a Bitcard code', /does not look like a Bitcard code/i.test(els.cardStatus.textContent));
  els.cardUri.value = CARD_101; els.cardUri.dispatch('input');
  ok('valid card: routes enabled', !els.pathGive.disabled && !els.pathClaim.disabled && !els.pathBal.disabled);
  ok('valid card: box collapses', els.cardBox.classList.contains('hide'));
  ok('valid card: change-card link offered', !els.changeCard.classList.contains('hide'));
}

// ---------------- 2. GIVE: address must never precede verification ----------------
{
  const { els } = boot();
  els.cardUri.value = CARD_101; els.cardUri.dispatch('input');
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
  els.cardUri.value = CARD_101; els.cardUri.dispatch('input');
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
  els.cardUri.value = CARD_101; els.cardUri.dispatch('input');
  els.pathGive.onclick(); els.setupBtn.onclick(); await tick();
  const grid = els.setupOut.textContent;
  const words=[]; for(let i=1;i<=12;i++){ words.push(grid.match(new RegExp('(?:^|\\s)'+i+'\\.\\s+([a-z]+)'))[1]); }
  els.verifyWords.value = words.join(' '); els.verifyBtn.onclick(); await tick();
  els.arriveBtn.onclick(); await tick(150);
  ok('give: confirmed funds ARE called ready to give', /ready to give/i.test(els.arriveOut.textContent));
}

// ---------------- 4. CLAIM: destination edit after Review must invalidate the draft ----------------
// Deliberately NOT the card's own address. When the destination equalled the source, a build that paid the
// card back to itself instead of to the recipient passed every assertion. This is the BIP173 test-vector
// address (hash160 of the secp256k1 generator), unrelated to any card.
const DEST = 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4';
const DEST_SPK = '0014751e76e8199196d454941c45d1b3a323f1433bd6';   // what the paying output MUST contain
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
  ok('claim: forced send after edit does NOT broadcast', !/✓ Sent/.test(els.bcastOut.textContent), els.bcastOut.textContent.slice(0,90));
  ok('claim: forced send tells user to review again', /Review before sending/i.test(els.bcastOut.textContent));
}

// The test above changes the box AND fires the input handler, which clears the draft before Send is even
// reached, so it never exercises the Send-time destination comparison. Removing that comparison entirely
// left every test green. This changes the value WITHOUT dispatching input, which is the case a hostile
// page or a stale autofill produces, and is the only path that reaches the final check.
{
  const els = await claimToReview();
  els.dest.value = 'bc1q6h6zqgr7pzgf4e2j86f2v4m60r5p0wqrvtkvyg';   // silently swapped, no input event
  els.destConfirm.checked = true;
  await els.bcastBtn.onclick(); await tick(200);
  ok('silent destination swap: does NOT broadcast', !/✓ Sent/.test(els.bcastOut.textContent), els.bcastOut.textContent.slice(0,120));
  ok('silent destination swap: says the address changed', /address changed after you reviewed/i.test(els.bcastOut.textContent), els.bcastOut.textContent.slice(0,140));
}

// The signed transaction must actually pay the reviewed destination, decoded from the broadcast bytes.
// With the test destination set to the card's own address, a build that paid the card back to itself
// passed everything; the assertion has to name an address unrelated to the card.
{
  let posted = null;
  const net = { utxos:[utxo(200000,true)] };
  const els = await claimToReview(net);
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, opts) => { if(opts && opts.method === 'POST') posted = opts.body; return realFetch(url, opts); };
  els.destConfirm.checked = true;
  await els.bcastBtn.onclick(); await tick(200);
  ok('broadcast happened', posted !== null);
  if(posted){
    const tx = btc.Transaction.fromRaw(hex.decode(posted.trim()));
    ok('the signed transaction has exactly one output', tx.outputsLength === 1, String(tx.outputsLength));
    ok('the output pays the reviewed destination, not the card',
       hex.encode(tx.getOutput(0).script) === DEST_SPK, hex.encode(tx.getOutput(0).script));
    ok('the output does NOT pay back to the card', hex.encode(tx.getOutput(0).script) !== CARD_SPK);
    // Isolate the check that ties the witness key to the PREVIOUS OUTPUT, not merely to itself. If that
    // oracle line is removed, this negative fixture must fail even though the signature and expected key
    // remain internally valid.
    const wrongChain = net.utxos.map(u=>({ ...u, scriptPubKey:DEST_SPK }));
    const wrongScriptReason = witnessValid(posted, hex.encode(CARD_PUB), wrongChain);
    ok('oracle rejects a valid witness when the real prevout locks to another key',
       /does not match the locking script/.test(wrongScriptReason||''), wrongScriptReason);
  }
}

// ---------------- 1b. A corrupted card code must be unusable, not merely discouraged ----------------
// v1 records carry no checksum, so a mistyped code can decode to a valid card holding a different key.
// Disabling the route buttons is presentation only: this harness calls handlers directly, exactly as a
// determined user or a scripted page could. The refusal has to live in the code path.
{
  const { els } = boot({ utxos:[utxo(200000,true)] });
  // CARD_VEC carries serial 90123, outside the minted range, so it must behave normally
  els.cardUri.value = CARD_VEC; els.cardUri.dispatch('input');
  ok('unminted serial: card outside our range still works', !els.pathClaim.disabled, els.cardStatus.textContent);

  // now claim a serial we DID mint while carrying a key we did not print
  const rec = [...Buffer.from(CARD_VEC.replace(/-/g,'+').replace(/_/g,'/'), 'base64')];
  rec[37]=0; rec[38]=0; rec[39]=0; rec[40]=123;                       // serial 123, inside 101..400
  const forged = Buffer.from(rec).toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
  els.cardUri.value = forged; els.cardUri.dispatch('input');
  ok('minted serial + wrong key: routes are disabled', els.pathClaim.disabled, els.cardStatus.textContent);
  ok('minted serial + wrong key: explains the code is wrong', /does not match the card we made/.test(els.cardStatus.textContent), els.cardStatus.textContent.slice(0,140));
  ok('minted serial + wrong key: carries the support code', /CARD-06/.test(els.cardStatus.textContent));

  // and the flow must refuse even when the handler is invoked directly, bypassing the disabled attribute
  els.pathClaim.onclick();
  els.claimP1.value = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
  els.claimP2.value = 'legal winner thank year wave sausage worth useful legal winner thank yellow';
  els.showBtn.onclick(); await tick(150);
  ok('minted serial + wrong key: fails closed when called directly', !/holds/.test(els.showOut.textContent), els.showOut.textContent.slice(0,120));
}

// A single boundary character changes both P1 and serial 101, escaping the issued ranges. The old test
// counted "unknown" as caught while the customer apps allowed funding. Exercise the real setup handlers.
{
  const { els } = boot();
  els.cardUri.value = CARD_101_BOUNDARY_MUTATION; els.cardUri.dispatch('input');
  ok('altered issued v1 -> unknown: Give route is disabled', els.pathGive.disabled, els.cardStatus.textContent);
  ok('altered issued v1 -> unknown: warning says not to add bitcoin', /Do not add bitcoin|cannot be used to add bitcoin/i.test(els.cardStatus.textContent));
  els.pathGive.onclick();
  ok('altered issued v1 -> unknown: direct Give handler cannot enter setup', els.giveFlow.classList.contains('hide'));
  els.setupBtn.onclick(); await tick();
  ok('altered issued v1 -> unknown: direct setup handler emits no words or funding address',
     !/Write these 12 words|Send bitcoin to this address/.test(els.setupOut.textContent+els.fundOut.textContent));
  ok('altered issued v1 -> unknown: Claim remains available for recovery with both halves', !els.pathClaim.disabled);
}

// ---------------- 4a. The Part 1 pairing gate must not be removable unnoticed ----------------
// The scratch-panel words must reproduce the P1 committed in the card's QR. Disabling that comparison left
// every UI test green, because nothing used a VALID Part 1 belonging to a DIFFERENT card. Both phrases here
// are individually valid BIP39; only their pairing with this card is wrong, which is the real-world case
// (two cards open on a table, panels scratched, phrases swapped between them).
{
  const { els } = boot({ utxos:[utxo(200000,true)] });
  els.cardUri.value = CARD_VEC; els.cardUri.dispatch('input');
  els.pathClaim.onclick();
  els.claimP1.value = 'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong';   // valid words, wrong card
  els.claimP2.value = CLAIM_P2;
  els.showBtn.onclick(); await tick(200);
  const t = els.showOut.textContent;
  ok('wrong-card Part 1: refuses, no balance shown', !/holds/i.test(t), t.slice(0,120));
  ok('wrong-card Part 1: names the scratch-panel words', /scratch/i.test(t), t.slice(0,160));
  ok('wrong-card Part 1: carries the pairing support code', /CARD-02/.test(t), t.slice(0,160));
  ok('wrong-card Part 1: send section stays hidden', els.sendSection.classList.contains('hide'));
  ok('wrong-card Part 1: the typed words are still there to correct', els.claimP1.value !== '' && els.claimP2.value !== '');
}
// the halves swapped between the two boxes is the commonest version of the same mistake, and gets its own message
{
  const { els } = boot({ utxos:[utxo(200000,true)] });
  els.cardUri.value = CARD_VEC; els.cardUri.dispatch('input');
  els.pathClaim.onclick();
  els.claimP1.value = CLAIM_P2; els.claimP2.value = CLAIM_P1;   // swapped
  els.showBtn.onclick(); await tick(200);
  const t = els.showOut.textContent;
  ok('swapped halves: refuses', !/holds/i.test(t), t.slice(0,120));
  ok('swapped halves: says they are in the wrong boxes', /wrong boxes|swap/i.test(t), t.slice(0,160));
}

// ---------------- 4a2. A flooded card must explain the recovery path, not look like a network fault -------
// The deposit address is public, so anyone can send hundreds of tiny payments to it. Past MAX_UTXOS the app
// refuses to build a sweep, which is correct. What was wrong was the wording: the raw internal message
// reached the customer, and on the balance path it was reported as a network failure, which sends someone
// to check their wifi forever when the actual answer is the offline tool. The bitcoin is never lost here.
{
  const flood = Array.from({ length: 501 }, (_, i) => ({
    txid: i.toString(16).padStart(64, '0'), vout: 0, value: 800, status: { confirmed: true }, scriptPubKey: CARD_SPK }));
  const { els } = boot({ utxos: flood });
  els.cardUri.value = CARD_VEC; els.cardUri.dispatch('input');
  els.pathClaim.onclick();
  els.claimP1.value = CLAIM_P1; els.claimP2.value = CLAIM_P2;
  els.showBtn.onclick(); await tick(250);
  const t = els.showOut.textContent;
  ok('flooded card: does not claim the network is unreachable', !/could not reach the bitcoin network/i.test(t), t.slice(0,110));
  ok('flooded card: says nothing was sent and the bitcoin is safe', /Nothing was sent/i.test(t) && /lost/i.test(t), t.slice(0,140));
  ok('flooded card: points at the offline tool', /offline\.html/.test(t));
  ok('flooded card: names a wallet that can sweep it', /Sparrow|Electrum/.test(t));
  ok('flooded card: carries a support code', /UTXO-02/.test(t));
  ok('flooded card: no raw internal wording leaks', !/toomanyinputs|refusing to sign/.test(t), t.slice(0,110));
}

// ---------------- 4b. CLAIM: a deposit arriving between Review and Send must not be left behind ----------
// External review, 2026-08-03, principal blocker. Review builds a draft from a snapshot of the card's coins.
// If another payment lands before Send, broadcasting the stale draft sweeps only the coins we knew about,
// and the success screen then told the customer the card was spent for good and to stop using it. The
// bitcoin is not gone, but the words usually are. Nothing else in the suite covered the mid-flow window.
{
  const net = { utxos:[utxo(200000,true)] };
  const els = await claimToReview(net);
  ok('late deposit: review succeeded on the original coin', /Nothing has been sent yet/i.test(els.claimOut.textContent));

  net.utxos.push({ txid:'c'.repeat(64), vout:0, value:300000, status:{confirmed:true} });   // second payment arrives
  els.destConfirm.checked = true;
  await els.bcastBtn.onclick(); await tick(200);

  // match the success marker, not /sent/i: the refusal text itself contains "nothing was sent"
  ok('late deposit: does NOT broadcast the stale draft', !/✓ Sent/.test(els.bcastOut.textContent), els.bcastOut.textContent.slice(0,120));
  ok('late deposit: says the balance changed', /changed while you were checking/i.test(els.bcastOut.textContent));
  ok('late deposit: carries the support code', /UTXO-01/.test(els.bcastOut.textContent));
  ok('late deposit: sends the customer back to Review', /Review before sending/i.test(els.bcastOut.textContent));
  ok('late deposit: hides the send button until re-reviewed', els.bcastBtn.classList.contains('hide'));

  // re-reviewing must pick up BOTH coins, otherwise the guard just blocks the claim forever
  els.reviewBtn.onclick(); await tick(200);
  ok('late deposit: re-review now includes both coins (500000 sats)', /500,?000/.test(els.claimOut.textContent), els.claimOut.textContent.slice(0,140));
}

// A vanishing coin is the same defect mirrored: the draft would be invalid, and silently retrying is worse
// than stopping. Also covers both nodes having been briefly behind at Review.
{
  const net = { utxos:[utxo(200000,true), { txid:'d'.repeat(64), vout:1, value:70000, status:{confirmed:true} }] };
  const els = await claimToReview(net);
  net.utxos.pop();
  els.destConfirm.checked = true;
  await els.bcastBtn.onclick(); await tick(200);
  ok('coin disappears before send: refuses to broadcast', !/✓ Sent/.test(els.bcastOut.textContent), els.bcastOut.textContent.slice(0,120));
}

// The success screen must never assert the card is empty. We only ever know that one payment left.
{
  const net = { utxos:[utxo(200000,true)] };
  const els = await claimToReview(net);
  els.destConfirm.checked = true;
  await els.bcastBtn.onclick(); await tick(200);
  const t = els.bcastOut.textContent;
  ok('success: broadcast succeeded when nothing changed', /Sent\./i.test(t), t.slice(0,120));
  ok('success: does NOT claim the card is spent for good', !/spent for good/i.test(t), t.slice(0,200));
  ok('success: tells the customer to verify zero before discarding', /shows zero/i.test(t), t.slice(0,240));
}

// ---------------- 5. CLAIM: broadcast requires independent observation ----------------
{
  // The lying-acceptor scenario: ONE node accepts and vouches for its own broadcast, the other rejects
  // and never sees it. A single self-interested witness must not be reported as a clean success.
  // NOTE ON TIMING: net.js retries observation after 4s before giving up, so a short wait here would
  // assert against "Sending..." and pass without ever seeing the final message. Await the handler, then
  // wait past the retry window.
  const els = await claimToReview({
    utxos:[utxo(200000,true)],
    rejectPost: url => /mempool\.space/.test(url),
    observedBy: url => /blockstream/.test(url)
  });
  els.destConfirm.checked = true;
  await els.bcastBtn.onclick();
  await tick(5000);
  const t = els.bcastOut.textContent;
  ok('claim: acceptor-only broadcast is not still mid-flight when asserted', !/Sending/i.test(t), t.slice(0,110));
  // no claim that the payment succeeded or is travelling. ("cannot be sent twice" appears later as safety
  // advice and is fine; what must not appear is an assertion that it went through.)
  ok('claim: acceptor-only broadcast never claims it went through or is on its way',
     !/(went through|on its way|is on the way|payment succeeded)/i.test(t), t.slice(0,140));
  ok('claim: acceptor-only broadcast does not open with a success tick', !/^\s*✓/.test(t), t.slice(0,60));
  ok('claim: acceptor-only broadcast states no second server has seen it',
     /no second server has seen it/i.test(t), t.slice(0,140));
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
  const els = await claimToReview();
  els.claimP2.value = 'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong';
  els.claimP2.dispatch('input');
  ok('state: editing either phrase invalidates the old balance and signed plan',
    els.sendSection.classList.contains('hide') && els.claimOut.textContent === '');
  els.destConfirm.checked = true;
  els.bcastBtn.onclick(); await tick(100);
  ok('state: forced Send after phrase edit cannot broadcast', !/Sent\./i.test(els.bcastOut.textContent));
}
{
  // same attack via the URL fragment rather than the box
  const els = await claimToReview();
  globalThis.location.hash = '#' + CARD_999;
  els; globalThis.window.dispatch('hashchange'); await tick();
  ok('state: hashchange to another card clears typed words', els.claimP1.value === '' && els.claimP2.value === '');
  ok('state: hashchange returns to chooser', !els.chooser.classList.contains('hide'));
}

// Deferred network work belongs to the context that started it. Resolving after a reset must not restore
// an old balance/review, and a destination changed while the final UTXO check waits must never reach POST.
{
  let release; const gate = new Promise(r=>{ release=r; });
  const net = { utxos:[utxo(200000,true)], beforeUtxo:()=>gate };
  const { els } = boot(net);
  els.cardUri.value = CARD_VEC; els.cardUri.dispatch('input'); els.pathClaim.onclick();
  els.claimP1.value = CLAIM_P1; els.claimP2.value = CLAIM_P2;
  const pending = els.showBtn.onclick(); await tick(20);
  els.cardUri.value = CARD_999; els.cardUri.dispatch('input');
  release(); await pending; await tick();
  ok('race: obsolete balance response does not repopulate the new card context', els.showOut.textContent === '');
  ok('race: obsolete balance response does not reveal Send', els.sendSection.classList.contains('hide'));
}
{
  const net = { utxos:[utxo(200000,true)] };
  const { els } = boot(net);
  els.cardUri.value = CARD_VEC; els.cardUri.dispatch('input'); els.pathClaim.onclick();
  els.claimP1.value = CLAIM_P1; els.claimP2.value = CLAIM_P2;
  els.showBtn.onclick(); await tick(150);
  let release; const gate = new Promise(r=>{ release=r; }); net.beforeUtxo=()=>gate;
  els.dest.value = DEST;
  const pending = els.reviewBtn.onclick(); await tick(20);
  els.cardUri.value = CARD_999; els.cardUri.dispatch('input');
  release(); await pending; await tick();
  ok('race: obsolete Review cannot restore a signed plan after card change', els.claimOut.textContent === '');
  ok('race: obsolete Review cannot restore the Send controls', els.bcastBtn.classList.contains('hide'));
}
{
  const net = { utxos:[utxo(200000,true)] };
  const els = await claimToReview(net);
  let release; const gate = new Promise(r=>{ release=r; }); net.beforeUtxo=()=>gate;
  els.destConfirm.checked=true;
  const pending=els.bcastBtn.onclick(); await tick(20);
  els.dest.value='bc1q6h6zqgr7pzgf4e2j86f2v4m60r5p0wqrvtkvyg'; // silent edit, no input event
  release(); await pending; await tick();
  ok('race: destination edit during final UTXO check produces zero POSTs', (net.postCount||0)===0, net.postCount);
}
{
  const net = { utxos:[utxo(200000,true)] };
  const els = await claimToReview(net);
  let release; const gate = new Promise(r=>{ release=r; }); net.beforePost=()=>gate;
  els.destConfirm.checked=true;
  const pending=els.bcastBtn.onclick(); await tick(20);
  globalThis.window.dispatch('pagehide');
  release(); await pending; await tick();
  ok('race: a POST response after pagehide does not restore a stale receipt', els.bcastOut.textContent==='');
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
  els.cardUri.value = CARD_101; els.cardUri.dispatch('input');
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
