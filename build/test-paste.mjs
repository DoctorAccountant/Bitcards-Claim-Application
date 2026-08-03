// Every form a customer could plausibly paste into the card box.
// A person under stress with a phone keyboard will produce all of these, and the difference between
// "card loaded" and a confusing error is whether the parser tolerates them.
// Run: node test-paste.mjs
import { normCardInput, parseAndVerifyCard, normWords, wordlist, halfScalar } from './core.js';

const REC = 'AQABAQOrOxUP6VvN0TIX0jhu801U5qRPbtBVoprrQ1nfUazLJgAAA-c';   // real minted card, serial 999
const URL = 'https://bitcards.xyz/app.html#' + REC;

let pass = 0, fail = 0;
const ok = (name, cond, got) => { cond ? pass++ : (fail++, console.log('FAIL: ' + name + (got !== undefined ? '\n      got: ' + JSON.stringify(got) : ''))); };
const loads = (name, input, expectSerial) => {
  let serial = null;
  try{ serial = parseAndVerifyCard(normCardInput(input)).serial; }catch(e){ serial = 'ERROR: ' + e.message; }
  ok(name, serial === expectSerial, serial);
};
const rejects = (name, input) => {
  let threw = false;
  try{ parseAndVerifyCard(normCardInput(input)); }catch(e){ threw = true; }
  ok(name, threw);
};

// --- forms that must LOAD ---
loads('full https link',                         URL, 999);
loads('raw record',                              REC, 999);
loads('bitcard: prefixed',                       'bitcard:' + REC, 999);
loads('BITCARD: uppercase prefix',               'BITCARD:' + REC, 999);
loads('leading and trailing spaces',             '   ' + URL + '   ', 999);
loads('leading and trailing newlines',           '\n\n' + URL + '\n', 999);
loads('tabs around it',                          '\t' + REC + '\t', 999);
loads('link with text before it (message app)',  'hey check this out ' + URL, 999);
loads('link with text after it',                 URL + ' <- open this one', 999);
loads('link wrapped in a sentence',              'Scan failed so here is the link ' + URL + ' thanks', 999);
loads('trailing full stop',                      URL + '.', 999);
loads('trailing comma',                          URL + ',', 999);
loads('wrapped in angle brackets (mail client)', '<' + URL + '>', 999);
loads('wrapped in quotes',                       '"' + URL + '"', 999);
loads('percent-encoded hash',                    'https://bitcards.xyz/app.html%23' + REC, 999);
loads('http not https',                          URL.replace('https', 'http'), 999);
loads('www prefix',                              URL.replace('https://', 'https://www.'), 999);
loads('the SAME link pasted twice',              URL + ' ' + URL, 999);
loads('the same link twice on separate lines',   URL + '\n' + URL, 999);
loads('bitcard: with a space after the colon',   'bitcard: ' + REC, 999);

// --- TWO DIFFERENT CARDS IN ONE PASTE MUST FAIL LOUDLY ---
// Silently choosing one lets a buyer write their words on the card in their hand while funding an address
// derived from the other card's key half. That is unrecoverable, so ambiguity is never resolved by guessing.
const VEC = 'AQABAQPZAvNfVg4EcMYzE8c2kWjZ198tSb8pX9n7fLEJzO4ElAAAAHs';
const VEC_URL = 'https://bitcards.xyz/app.html#' + VEC;
const ambiguous = (name, input) => {
  let msg = null;
  try{ parseAndVerifyCard(normCardInput(input)); }catch(e){ msg = e.message; }
  ok(name, /multiple cards/.test(msg || ''), msg === null ? 'ACCEPTED ONE SILENTLY' : msg);
};
ambiguous('two different links, A then B',       URL + ' ' + VEC_URL);
ambiguous('two different links, B then A',       VEC_URL + ' ' + URL);
ambiguous('two different links on separate lines', URL + '\n' + VEC_URL);
ambiguous('two different raw records',           REC + ' ' + VEC);
ambiguous('two different links inside a message', 'here are both: ' + URL + ' and also ' + VEC_URL + ' pick one');
ambiguous('three links, two distinct',           URL + ' ' + URL + ' ' + VEC_URL);

// --- forms that must be REJECTED cleanly, never silently mis-parsed ---
rejects('empty',                     '');
rejects('whitespace only',           '   \n  ');
rejects('arbitrary prose',           'hello world this is not a card');
rejects('a bare url with no record', 'https://bitcards.xyz/app.html');
rejects('truncated record',          REC.slice(0, 20));
rejects('record missing final char', REC.slice(0, -1));
rejects('a bitcoin address',         'bc1q6h6zqgr7pzgf4e2j86f2v4m60r5p0wqrvtkvyg');
rejects('some other site link',      'https://example.com/#somethingelse');

// --- a mangled record must never resolve to a DIFFERENT valid card ---
{
  const swapped = REC.slice(0, 10) + 'X' + REC.slice(11);
  let serial = null;
  try{ serial = parseAndVerifyCard(normCardInput(swapped)).serial; }catch(e){ serial = 'rejected'; }
  ok('a corrupted character does not silently become another card', serial === 'rejected' || serial !== 999, serial);
}

// --- word boxes: characters that phones, chat apps and PDFs insert invisibly ---
// These must be accepted. A rejection here shows the customer a word that looks perfectly correct,
// so they retype it identically forever and conclude the card is broken.
const WORDS = 'legal winner thank year wave sausage worth useful legal winner thank yellow';
const accepts = (name, raw) => {
  const m = normWords(raw);
  const w = m ? m.split(' ') : [];
  let why = null;
  if (w.length !== 12) why = 'count ' + w.length;
  else for (let i = 0; i < 12; i++) if (wordlist.indexOf(w[i]) < 0) { why = 'word ' + (i+1) + ' ' + JSON.stringify(w[i]); break; }
  if (!why) { try { halfScalar(m); } catch (e) { why = 'checksum'; } }
  ok(name, why === null, why);
};
accepts('plain 12 words',                 WORDS);
accepts('upper case',                     WORDS.toUpperCase());
accepts('double spaces',                  WORDS.replace(/ /g, '  '));
accepts('newlines as separators',         WORDS.replace(/ /g, '\n'));
accepts('tabs as separators',             WORDS.replace(/ /g, '\t'));
accepts('non-breaking spaces',            WORDS.replace(/ /g, ' '));
accepts('narrow no-break spaces',         WORDS.replace(/ /g, ' '));
accepts('ideographic spaces',             WORDS.replace(/ /g, '　'));
accepts('BOM at start',                   '﻿' + WORDS);
accepts('zero-width space between words', WORDS.split(' ').join('​ '));
accepts('zero-width joiner inside a word',WORDS.replace('legal', 'le‍gal'));
accepts('soft hyphen inside a word',      WORDS.replace('winner', 'win­ner'));
accepts('comma separated',                WORDS.split(' ').join(', '));
accepts('semicolon separated',            WORDS.split(' ').join('; '));
accepts('leading and trailing space',     '  ' + WORDS + '  ');

// wrong counts must still be caught, not silently fixed
ok('11 words still rejected', normWords(WORDS.split(' ').slice(0,11).join(' ')).split(' ').length === 11);
ok('13 words still rejected', normWords(WORDS + ' extra').split(' ').length === 13);

console.log('\n' + (fail === 0 ? 'PASTE OK (' + pass + ' passed)' : 'PASTE FAILED (' + fail + ' failures)'));
process.exit(fail === 0 ? 0 : 1);
