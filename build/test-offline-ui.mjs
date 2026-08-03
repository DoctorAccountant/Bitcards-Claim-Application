// Drives the REAL built offline bundle against a minimal DOM, in both live (gated) and file:// (unlocked) modes.
// Verifies the setup-time fix end to end: words are generated on-device, a deposit address is derived from the
// card's PUBLIC half, re-typing verifies, wrong words are rejected, and nothing leaks between cards.
import fs from 'node:fs';

const BUNDLE = process.argv[2];
const IDS = ['netbadge','cardUri','cardStatus','modeSetup','modeOpen','setupCard','setupBack','genBtn','genOut',
  'setupResult','outWords','outSetupAddr','verifyWords','verifyBtn','verifyOut','setupDone','openCard','openBack',
  'p1','wc1','p2','wc2','revealBtn','keyOut','resultBox','outAddr','outWif','copyWif','clearBtn','liveGate','dlLink',
  'buildhash','status','appbundle','addrBox','haveWordsBtn','haveWordsCard','haveBack','haveWords','haveCheckBtn','haveOut'];
const HIDDEN_AT_START = ['setupCard','openCard','setupResult','resultBox','liveGate','addrBox','haveWordsCard'];

function makeEl(id){
  const cls = new Set(HIDDEN_AT_START.includes(id) ? ['hide'] : []);
  return {
    id, value: '', textContent: '', disabled: false, className: '', style: { cssText: '' }, onclick: null,
    classList: {
      add: c => cls.add(c), remove: c => cls.delete(c), contains: c => cls.has(c),
      toggle: (c, on) => { if (on === undefined) { cls.has(c) ? cls.delete(c) : cls.add(c); } else { on ? cls.add(c) : cls.delete(c); } }
    },
    _handlers: {},
    addEventListener(ev, fn){ (this._handlers[ev] = this._handlers[ev] || []).push(fn); },
    dispatch(ev){ (this._handlers[ev] || []).forEach(fn => fn({ target: this })); },
    appendChild(child){ this.textContent += child.textContent; },
    scrollIntoView(){}, focus(){}
  };
}

function run({ live, onConfirm }){
  const els = {};
  for (const id of IDS) els[id] = makeEl(id);
  els.appbundle.textContent = '';   // showBuildHash takes the "not bundled" branch

  const confirmAnswers = [];
  globalThis.document = {
    title: '',
    getElementById: id => els[id] || null,
    createElement: () => ({ className: '', textContent: '', href: '', target: '', rel: '', appendChild(){} }),
    createTextNode: t => ({ textContent: t })
  };
  globalThis.window = {
    addEventListener(){}, scrollTo(){},
    location: { protocol: live ? 'https:' : 'file:', hash: '' }
  };
  globalThis.location = globalThis.window.location;
  globalThis.confirm = (msg) => (onConfirm ? onConfirm(msg) : (confirmAnswers.length ? confirmAnswers.shift() : true));
  try{ Object.defineProperty(globalThis, 'navigator', { value: { clipboard: { writeText(){} } }, configurable: true }); }catch(e){}

  const src = fs.readFileSync(BUNDLE, 'utf8');
  new Function(src)();   // executes init()
  return { els, confirmAnswers };
}

let pass = 0, fail = 0;
const ok = (name, cond) => { cond ? pass++ : (fail++, console.log('FAIL: ' + name)); };

const CARD_101 = 'AQABAQNeyFBDvBKLzkvd64SOllZZHCuKXg4IsZ9iuQLKISgIOwAAAGU';
const CARD_201 = 'AQABAQLfRDXIEvQOzzQua7XN1bX0GV4ADGLZhtcuHx0nACm7lgAAAMk';

// ---- 1. LIVE (https) must refuse to generate or reveal anything ----
{
  const { els } = run({ live: true });
  ok('live: gate banner shown', !els.liveGate.classList.contains('hide'));
  ok('live: generate button disabled', els.genBtn.disabled === true);
  ok('live: reveal button disabled', els.revealBtn.disabled === true);
  ok('live: word inputs disabled', els.p1.disabled && els.p2.disabled && els.verifyWords.disabled);
  // force the setup handler anyway: must produce no words and no address
  els.cardUri.value = CARD_101; els.cardUri.dispatch('input');
  els.modeSetup.onclick();
  if (els.genBtn.onclick) els.genBtn.onclick();
  ok('live: forced generate produces NO words', els.outWords.textContent === '');
  ok('live: forced generate produces NO address', els.outSetupAddr.textContent === '');
}

// ---- 2. FILE (offline) unlocks and the setup fix works ----
{
  const { els } = run({ live: false });
  ok('offline: gate hidden', els.liveGate.classList.contains('hide'));
  ok('offline: generate enabled', els.genBtn.disabled === false);
  ok('offline: status says ready', /ready/i.test(els.status.textContent));

  els.cardUri.value = CARD_101; els.cardUri.dispatch('input');
  ok('offline: card 101 recognised', /card loaded \(No\. 101\)/.test(els.cardStatus.textContent));

  els.modeSetup.onclick();
  ok('offline: setup panel opened', !els.setupCard.classList.contains('hide'));

  els.genBtn.onclick();
  const grid = els.outWords.textContent;
  const words = [...grid.matchAll(/\d+\.\s+([a-z]+)/g)].map(m => m[1]);
  ok('offline: 12 words generated', words.length === 12);
  ok('offline: result panel shown', !els.setupResult.classList.contains('hide'));
  ok('offline: confirms work stayed on device', /this device/i.test(els.genOut.textContent));
  // THE CORE SAFETY RULE: the deposit address must NOT appear until the words are verified.
  // Funding an address whose words were miscopied is unrecoverable.
  ok('offline: address hidden before verification', els.outSetupAddr.textContent === '');
  ok('offline: address panel hidden before verification', els.addrBox.classList.contains('hide'));

  // a WRONG set must be rejected AND must not reveal the address
  const ordered = [];
  for (let i = 1; i <= 12; i++) { const m = grid.match(new RegExp('(?:^|\\s)' + i + '\\.\\s+([a-z]+)')); ordered.push(m[1]); }
  els.verifyWords.value = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
  els.verifyBtn.onclick();
  ok('offline: wrong words rejected', /do not match the 12 shown above/i.test(els.verifyOut.textContent));
  ok('offline: address still hidden after a wrong re-type', els.outSetupAddr.textContent === '' && els.addrBox.classList.contains('hide'));

  // the CORRECT re-type reveals it
  els.verifyWords.value = ordered.join(' ');
  els.verifyBtn.onclick();
  ok('offline: correct re-type verifies', /your writing matches/i.test(els.verifyOut.textContent));
  ok('offline: verify box cleared after success', els.verifyWords.value === '');
  const addr = els.outSetupAddr.textContent.trim();
  ok('offline: address revealed only now, mainnet bech32', /^bc1q[0-9a-z]{38}$/.test(addr));
  ok('offline: address panel shown', !els.addrBox.classList.contains('hide'));

  // once verified, regeneration is locked: new words would abandon a card that may already be funded
  els.genBtn.onclick();
  ok('offline: regeneration locked after verification', /disabled/i.test(els.genOut.textContent));
  ok('offline: locked regeneration did not change the words', els.outWords.textContent === grid);

  // switching cards must wipe the previous card's words and address
  els.cardUri.value = CARD_201; els.cardUri.dispatch('input');
  ok('card switch: words cleared', els.outWords.textContent === '');
  ok('card switch: address cleared', els.outSetupAddr.textContent === '');
  ok('card switch: setup panel hidden', els.setupResult.classList.contains('hide'));
  ok('card switch: address panel hidden', els.addrBox.classList.contains('hide'));

  // a second card generates its own distinct words, and its address is likewise gated behind verification
  els.modeSetup.onclick(); els.genBtn.onclick();
  const grid2 = els.outWords.textContent;
  ok('second card generated its own words', grid2 !== '' && grid2 !== grid);
  ok('second card address also gated', els.outSetupAddr.textContent === '');
  const ordered2 = [];
  for (let i = 1; i <= 12; i++) { const m = grid2.match(new RegExp('(?:^|\\s)' + i + '\\.\\s+([a-z]+)')); ordered2.push(m[1]); }
  els.verifyWords.value = ordered2.join(' ');
  els.verifyBtn.onclick();
  const secondAddr = els.outSetupAddr.textContent.trim();
  ok('second card address revealed after verify', /^bc1q/.test(secondAddr));
  ok('second card address differs from first', secondAddr !== addr);
  els.setupDone.onclick();
  ok('done: words cleared', els.outWords.textContent === '');
  ok('done: address cleared', els.outSetupAddr.textContent === '');
}

// ---- 2b. The non-generating "I already wrote words" route ----
{
  const { els } = run({ live: false });
  els.cardUri.value = CARD_101; els.cardUri.dispatch('input');
  els.haveWordsBtn.onclick();
  ok('have-words: panel opened', !els.haveWordsCard.classList.contains('hide'));
  els.haveWords.value = 'legal winner thank year wave sausage worth useful legal winner thank yellow';
  els.haveCheckBtn.onclick();
  ok('have-words: derives an address', /bc1q[0-9a-z]{38}/.test(els.haveOut.textContent));
  ok('have-words: warns if it is not the funded address', /NOT the address you funded/i.test(els.haveOut.textContent));
  ok('have-words: generated NOTHING (no words produced)', els.outWords.textContent === '');
}

// ---- 2c. A reload (fresh session) must re-ask the blank-card question before generating ----
{
  let asked = 0;
  const { els } = run({ live: false, onConfirm: (msg) => { if (/BLANK/i.test(msg)) asked++; return true; } });
  els.cardUri.value = CARD_101; els.cardUri.dispatch('input');
  els.modeSetup.onclick();
  els.genBtn.onclick();
  ok('fresh session: blank-card question was asked before generating', asked === 1);
  ok('fresh session: words were generated after confirming', els.outWords.textContent !== '');
}

// ---- 2d. Declining the blank-card question must generate nothing ----
{
  const { els } = run({ live: false, onConfirm: () => false });
  els.cardUri.value = CARD_101; els.cardUri.dispatch('input');
  els.modeSetup.onclick();
  els.genBtn.onclick();
  ok('declining the blank-card question generates nothing', els.outWords.textContent === '');
  ok('declining leaves the address hidden', els.outSetupAddr.textContent === '');
}

// ---- 3. OPEN mode still works (regression) ----
{
  const { els } = run({ live: false });
  els.cardUri.value = 'AQABAQPZAvNfVg4EcMYzE8c2kWjZ198tSb8pX9n7fLEJzO4ElAAAAHs';   // vector card, serial 123
  els.cardUri.dispatch('input');
  els.modeOpen.onclick();
  ok('open: panel shown', !els.openCard.classList.contains('hide'));
  els.p1.value = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
  els.p2.value = 'legal winner thank year wave sausage worth useful legal winner thank yellow';
  els.revealBtn.onclick();
  ok('open: reproduces the frozen vector address', els.outAddr.textContent === 'bc1q6h6zqgr7pzgf4e2j86f2v4m60r5p0wqrvtkvyg');
  ok('open: reproduces the frozen vector WIF', els.outWif.textContent === 'L2GNgkXGSNjb1fTyt9WSbwHX8s3LwRRYNExo8AoBAg2yTDJMnXBF');
  ok('open: word inputs cleared after reveal', els.p1.value === '' && els.p2.value === '');
}

console.log('\n' + (fail === 0 ? 'OFFLINE SMOKE OK (' + pass + ' passed)' : 'OFFLINE SMOKE FAILED (' + fail + ')'));
process.exit(fail === 0 ? 0 : 1);
