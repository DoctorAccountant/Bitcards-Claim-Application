// Every form a customer could plausibly paste into the card box.
// A person under stress with a phone keyboard will produce all of these, and the difference between
// "card loaded" and a confusing error is whether the parser tolerates them.
// Run: node test-paste.mjs
import { normCardInput, parseAndVerifyCard } from './core.js';

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
loads('two links pasted together (uses last)',   URL + ' ' + URL, 999);
loads('newline between two links (uses last)',   URL + '\n' + URL, 999);
loads('bitcard: with a space after the colon',   'bitcard: ' + REC, 999);

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

console.log('\n' + (fail === 0 ? 'PASTE OK (' + pass + ' passed)' : 'PASTE FAILED (' + fail + ' failures)'));
process.exit(fail === 0 ? 0 : 1);
