// Bitcard network layer (ONLINE claim app only). Kept physically separate from core.js so the OFFLINE key tool,
// which imports only core.js, contains no fetch, no node URLs, and nothing that can reach the internet.
import { isTxid, validateUtxos } from './core.js';
import { ENDPOINTS } from './endpoints.js';

export const FETCH_TIMEOUT = 15000; // ms; a hung node must not freeze the app forever (§9)
export const MAX_RESPONSE_BYTES = 1024 * 1024; // public APIs should never need a megabyte for these calls
export async function fetchWithTimeout(url, opts, consume, timeoutMs = FETCH_TIMEOUT){
  const ac = new AbortController();
  const t = setTimeout(()=>ac.abort(), timeoutMs);
  try{
    const response = await fetch(url, Object.assign({}, opts, { signal: ac.signal }));
    // The deadline belongs to the COMPLETE operation. Returning at headers and clearing the timer lets a
    // hostile node keep response.text()/json() pending forever. Consumers therefore run under this timer.
    return consume ? await consume(response) : response;
  }
  finally{ clearTimeout(t); }
}
export async function responseText(r){
  const declared = Number(r.headers && r.headers.get && r.headers.get('content-length'));
  if(Number.isFinite(declared) && declared > MAX_RESPONSE_BYTES) throw new Error('response too large');
  // Enforce the cap while reading chunked/lengthless responses too. Calling response.text() first and
  // measuring afterwards still lets a hostile node allocate an arbitrarily large string in the page.
  if(r.body && typeof r.body.getReader === 'function'){
    const reader = r.body.getReader(), decoder = new TextDecoder();
    let total = 0, text = '';
    try{
      for(;;){
        const {done,value} = await reader.read(); if(done) break;
        total += value.byteLength;
        if(total > MAX_RESPONSE_BYTES){ try{ await reader.cancel(); }catch(e){} throw new Error('response too large'); }
        text += decoder.decode(value, {stream:true});
      }
      return text + decoder.decode();
    }finally{ try{ reader.releaseLock(); }catch(e){} }
  }
  const text = await r.text();
  if(new TextEncoder().encode(text).length > MAX_RESPONSE_BYTES) throw new Error('response too large');
  return text;
}
export async function fetchJSON(base, path){
  return fetchWithTimeout(base+path, undefined, async r => {
    if(!r.ok) throw new Error('http '+r.status);
    // Test doubles may expose json() only; awaiting it here still keeps the same abort deadline active.
    if(typeof r.text !== 'function') return r.json();
    const text = await responseText(r);
    try{ return JSON.parse(text); }catch(e){ throw new Error('invalid json'); }
  });
}

export async function getUtxos(addr){ // §7: require ALL nodes to respond, pass schema validation, AND agree before signing
  const NODES = ENDPOINTS.nodes;
  const res = await Promise.allSettled(NODES.map(b=>fetchJSON(b,'/address/'+addr+'/utxo')));
  const ok = res.filter(r=>r.status==='fulfilled').map(r=>r.value);
  if(ok.length < NODES.length) throw new Error('only '+ok.length+'/'+NODES.length+' nodes responded — refusing to sign; §7 requires agreement of all nodes');
  ok.forEach(validateUtxos);
  const key = u => u.map(x=>x.txid+':'+x.vout+':'+x.value+':'+(x.status&&x.status.confirmed?1:0)).sort().join(',');
  for(let i=1;i<ok.length;i++){ if(key(ok[i])!==key(ok[0])) throw new Error('nodes disagree on UTXO set/values — refusing to sign (§7)'); }
  return { utxos: ok[0], agreed: ok.length };
}

// Fee estimate from ALL nodes; use the LOWEST sane answer. A lying node can then only slow the payment (the RBF
// speed-up recovers that), never inflate the fee toward the 50% cap. Bounded by MAX_FEERATE + 50% cap + dust refusal.
// It used to fall back to 2 sat/vB in two places: when a node's JSON lacked the expected keys, and when
// every node failed. Both were silent. In a busy mempool a 2 sat/vB sweep can sit unconfirmed for weeks or
// be evicted entirely, while the app reports a txid and the customer files the card away believing it is
// done. Guessing a fee is never better than saying we do not know: the bitcoin is safe on the card either
// way, so we refuse and let them retry. A node that answers with nothing usable is now simply not counted.
export async function feeRate(){
  const NODES = ENDPOINTS.nodes;
  const res = await Promise.allSettled(NODES.map(b=>fetchJSON(b,'/fee-estimates')));
  const rates = res.filter(r=>r.status==='fulfilled')
    .map(r=>{
      const f = r.value || {};
      for(const k of ['2','3','6']){
        const v = Number(f[k]);
        if(Number.isFinite(v) && v > 0) return Math.ceil(v);
      }
      return null;                       // this node said nothing usable; excluded, never treated as cheap
    })
    .filter(x => x !== null && Number.isFinite(x) && x >= 1);
  if(!rates.length) throw new Error('nofee');
  return Math.max(1, Math.min(...rates));
}

export async function broadcastTx(raw, expectedTxid){ // §7: post to ALL nodes; a node "accepts" only if it echoes the txid WE computed (a lying node cannot fake success)
  const NODES = ENDPOINTS.nodes;
  const res = await Promise.allSettled(NODES.map(async b => {
    const out = await fetchWithTimeout(b+'/tx',{method:'POST',body:raw}, async r => ({ r, text:await responseText(r) }));
    const r = out.r, t = (out.text||'').trim();
    if(!r.ok) throw new Error(t || ('http '+r.status));
    if(!isTxid(t)) throw new Error('unexpected response (not a txid): '+t.slice(0,80));
    if(expectedTxid && t.toLowerCase() !== String(expectedTxid).toLowerCase()) throw new Error('node returned a different txid than the transaction we signed');
    return t;
  }));
  const accepted = [], errs = [];
  res.forEach((r,i)=>{ const host = NODES[i].split('//')[1]; if(r.status==='fulfilled'){ accepted.push({host, txid:r.value}); } else { errs.push(host+': '+(r.reason&&r.reason.message||r.reason)); } });
  if(!accepted.length) throw new Error('all nodes rejected: '+errs.join(' | '));
  const txid = accepted[0].txid;
  const acceptedHosts = accepted.map(a=>a.host);
  // Independent observation, tracked BY HOST (§7): a lying acceptor can echo the right txid and then 200 its own
  // status endpoint, so the acceptor's word is never enough. "Confirmed" requires ALL nodes to have accepted, or a
  // host that did NOT accept the broadcast to now see the tx. One retry allows for propagation between nodes.
  const checkObserved = async () => {
    const seen = [];
    await Promise.allSettled(NODES.map(async b => { try{ const r = await fetchWithTimeout(b+'/tx/'+txid+'/status'); if(r.ok) seen.push(b.split('//')[1]); }catch(e){} }));
    return seen;
  };
  let observedHosts = await checkObserved();
  const indep = hosts => acceptedHosts.length >= NODES.length || hosts.some(h => !acceptedHosts.includes(h));
  let independent = indep(observedHosts);
  if(!independent){
    await new Promise(r=>setTimeout(r, 4000));
    observedHosts = await checkObserved();
    independent = indep(observedHosts);
  }
  return { txid, acceptedHosts, observedHosts, independent, nodeCount: NODES.length, errs };
}
