// A real HTTP response that sends headers and part of its body, then never finishes. The old timeout was
// cleared at headers and this stayed pending forever. Keep the body read under the same deadline.
import http from 'node:http';
import { fetchWithTimeout, responseText, MAX_RESPONSE_BYTES } from './net.js';

let pass=0, fail=0;
const ok=(name,cond,detail)=>{ cond?pass++:(fail++,console.log('FAIL: '+name+(detail?'\n      '+detail:''))); };
const sockets=new Set();
const server=http.createServer((req,res)=>{
  res.writeHead(200,{'content-type':'application/json'});
  res.write('{"started":true');
});
server.on('connection',s=>{ sockets.add(s); s.on('close',()=>sockets.delete(s)); });
await new Promise((resolve,reject)=>{ server.once('error',reject); server.listen(0,'127.0.0.1',resolve); });
const port=server.address().port;
const started=Date.now(); let rejected=false;
try{
  await fetchWithTimeout('http://127.0.0.1:'+port+'/',undefined,r=>r.text(),150);
}catch(e){ rejected=true; }
const elapsed=Date.now()-started;
ok('stalled response body is aborted',rejected);
ok('body deadline includes the response read',elapsed<1500,'elapsed '+elapsed+' ms');
let largeRejected=false;
const oversized = new Response(new ReadableStream({ start(controller){
  controller.enqueue(new Uint8Array(MAX_RESPONSE_BYTES + 1)); controller.close();
}}), { headers:{'content-type':'application/json'} });
try{ await responseText(oversized); }
catch(e){ largeRejected=/response too large/.test(e.message); }
ok('chunked response is size-capped while streaming',largeRejected);
for(const s of sockets) s.destroy();
await new Promise(resolve=>server.close(resolve));
console.log(fail?'NETWORK DEADLINE FAILED ('+fail+' failures)':'NETWORK DEADLINE OK ('+pass+' passed)');
process.exit(fail?1:0);
