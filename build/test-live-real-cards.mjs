// THE question a boss actually asks: "will the 300 cards in the box work with the website as it is right now?"
// Everything else in the suite tests the code in this folder. This fetches the LIVE deployed app, confirms it
// is byte-identical to what we built, and then drives REAL minted card records (public data from the QC
// manifest, no words anywhere) through it exactly as a customer's scan would.
//
// Run: node test-live-real-cards.mjs [path-to-QC-manifest.json]
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

let pass = 0, fail = 0;
const ok = (n, c, d) => { c ? pass++ : (fail++, console.log('FAIL: ' + n + (d !== undefined ? '\n      ' + d : ''))); };

const MAN = process.argv[2] || process.env.BITCARD_MANIFEST || 'C:/Users/Cameron/bitcard-mint/bitcard-print-300-QC-manifest.json';
const LIVE = 'https://bitcardssetup.com/app.html';

// ---- 1. the live page is the page we built ----
let html;
try { const r = await fetch(LIVE, { cache: 'no-store' }); html = await r.text(); }
catch (e) { console.log('FAIL: could not reach ' + LIVE + ': ' + e.message); process.exit(1); }
const localHtml = readFileSync(new URL('claim-app.html', import.meta.url), 'utf8');
const h = s => createHash('sha256').update(s).digest('hex');
ok('live app is byte-identical to the local build', h(html) === h(localHtml),
   'live ' + h(html).slice(0, 16) + ' vs built ' + h(localHtml).slice(0, 16));

// ---- 2. run REAL cards through the LIVE bundle ----
const m = html.match(/<script[^>]*>([\s\S]*?)<\/script>/);
ok('live page carries an inline bundle', !!m);
const bundle = m ? m[1] : '';

const IDS = ['netbadge','cardChip','cardBox','cardUri','cardStatus','changeCard','pathGive','pathClaim','pathBal',
  'chooser','giveFlow','giveBack','setupBtn','setupOut','verifyWords','verifyBtn','verifyOut','fundBox','fundOut',
  'arriveBtn','arriveOut','claimFlow','claimBack','claimP1','wc1','claimP2','wc2','showBtn','showOut','retryBal',
  'sendSection','dest','genDest','destOut','reviewBtn','claimOut','confirmRow','destConfirm','bcastBtn','bcastOut',
  'bumpBtn','bumpOut','balFlow','balBack','balWords','balCheckBtn','balFlowOut','buildhash','selftest','status','appbundle'];
const HIDDEN = ['giveFlow','claimFlow','balFlow','fundBox','sendSection','confirmRow','bcastBtn','bumpBtn','retryBal','changeCard','cardChip'];

function boot(hash){
  const els = {};
  for (const id of IDS){
    const cls = new Set(HIDDEN.includes(id) ? ['hide'] : []);
    els[id] = { id, value:'', textContent:'', disabled:false, className:'', checked:false, style:{cssText:''}, onclick:null,
      classList:{ add:c=>cls.add(c), remove:c=>cls.delete(c), contains:c=>cls.has(c),
        toggle:(c,on)=>{ if(on===undefined){ cls.has(c)?cls.delete(c):cls.add(c); } else { on?cls.add(c):cls.delete(c); } } },
      _h:{}, addEventListener(ev,fn){ (this._h[ev]=this._h[ev]||[]).push(fn); },
      dispatch(ev){ (this._h[ev]||[]).forEach(fn=>fn({target:this})); },
      appendChild(c){ this.textContent += c.textContent||''; }, scrollIntoView(){}, focus(){}, select(){} };
  }
  globalThis.document = { title:'', getElementById:id=>els[id]||null,
    createElement:()=>({className:'',textContent:'',href:'',target:'',rel:'',appendChild(){}}),
    createTextNode:t=>({textContent:t}), querySelector:()=>null };
  const winH = {};
  globalThis.window = { addEventListener(ev,fn){ (winH[ev]=winH[ev]||[]).push(fn); }, scrollTo(){},
    dispatch(ev){ (winH[ev]||[]).forEach(fn=>fn({})); }, location:{ protocol:'https:', hash: hash || '' } };
  globalThis.location = globalThis.window.location;
  globalThis.confirm = () => true;
  globalThis.fetch = async () => ({ ok:true, status:200, json:async()=>[], text:async()=>'{}' });
  try{ Object.defineProperty(globalThis,'navigator',{value:{clipboard:{writeText(){}}},configurable:true}); }catch(e){}
  new Function(bundle)();
  return els;
}

let man = null;
try { man = JSON.parse(readFileSync(MAN, 'utf8')); } catch (e) {}
ok('QC manifest available to source real cards (set BITCARD_MANIFEST)', man !== null, MAN);

if (man && bundle) {
  // sample across the whole printed range, including both ends
  // A one-card proof manifest is legitimate. Keep every sample index in range and remove duplicates;
  // otherwise the post-deploy gate crashes while trying to read card -1 or card 1 instead of testing it.
  const idx = [...new Set([0, 1, Math.floor(man.cards.length/2), man.cards.length-2, man.cards.length-1]
    .filter(i => i >= 0 && i < man.cards.length))];
  let loaded = 0, routes = 0;
  for (const i of idx) {
    const c = man.cards[i];
    const els = boot('#' + c.recordB64);          // exactly what scanning the card's QR produces
    const version = Buffer.from(c.recordB64.replace(/-/g,'+').replace(/_/g,'/'), 'base64')[0];
    const exactLoaded = new RegExp('card loaded \\(No\\. ' + c.serial + '\\)').test(els.cardStatus.textContent);
    // A deliberately burned/unissued v1 proof card is recovery-only because it is absent from the issued
    // table. That is a valid, intentional state: its serial is still shown and Claim/Balance remain open,
    // but Give must stay closed because an unknown v1 record has no checksum.
    const recoveryOnly = version === 1 && els.cardChip.textContent === 'No. ' + c.serial &&
      /legacy card code/.test(els.cardStatus.textContent);
    if (exactLoaded || recoveryOnly) loaded++;
    if (!els.pathClaim.disabled && !els.pathBal.disabled &&
        (exactLoaded ? !els.pathGive.disabled : recoveryOnly && els.pathGive.disabled)) routes++;
  }
  ok('real cards load from their own QR fragment (' + loaded + '/' + idx.length + ')', loaded === idx.length);
  ok('real cards expose exactly the routes allowed for their record (' + routes + '/' + idx.length + ')', routes === idx.length);

  // and a one-character typo of a real card must be refused by the LIVE app
  const c0 = man.cards[0];
  const frag = c0.recordB64;
  let refused = 0, tried = 0;
  for (let i = 6; i < frag.length && tried < 12; i++) {
    const ch = frag[i] === 'A' ? 'B' : 'A';
    const bad = frag.slice(0, i) + ch + frag.slice(i + 1);
    if (bad === frag) continue;
    tried++;
    const els = boot('#' + bad);
    // safe outcomes: refused outright, or it decoded to the SAME card (harmless)
    const sameCard = new RegExp('No\\. ' + c0.serial + '\\)').test(els.cardStatus.textContent);
    // Claim intentionally remains open for structurally valid unknown v1 records because someone holding
    // both halves must always be able to recover. The safety invariant is that a changed record can never
    // be newly funded: Give is disabled unless the mutation still decodes to the exact same card.
    const blockedForFunding = els.pathGive.disabled;
    if (blockedForFunding || sameCard) refused++;
  }
  ok('typos cannot fund a different card in the LIVE app (' + refused + '/' + tried + ')', refused === tried);
}

console.log('\n' + (fail === 0 ? 'LIVE REAL CARDS OK (' + pass + ' passed)' : 'LIVE REAL CARDS FAILED (' + fail + ' failures)'));
process.exit(fail === 0 ? 0 : 1);
