const {test}=require('node:test');
const assert=require('node:assert/strict');
const http=require('node:http');
const net=require('node:net');
const https=require('node:https');
const {spawnSync}=require('node:child_process');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const {chromium}=require('playwright');
const {targets,pool,visit}=require('../browse.cjs');
test('queue preserves URL paths and mandatory profiles override duplicates',()=>{
  const result=targets('example.com\nhttps://example.com/\n# comment\nother.test',[
    {url:'https://example.com/',text:'Login',selector:'button'},
    {url:'https://tax.test/login',text:'Login',selector:'input'}]);
  assert.equal(result.length,3);assert.equal(result[0].required,true);assert.equal(result[2].url,'https://tax.test/login');
  assert.throws(()=>targets('example.com',[]));
});
test('10 workers, complete all items after a recorded failure',async()=>{
  let running=0,peak=0,done=0;
  const results=await pool(Array.from({length:25},(_,i)=>i),async i=>{
    running++;peak=Math.max(peak,running);await new Promise(r=>setTimeout(r,5));running--;done++;return {ok:i!==2};
  });
  assert.equal(peak,10);assert.equal(done,25);assert.equal(results.filter(r=>!r.ok).length,1);
});
// Minimal local SOCKS5 fixture: verifies Chromium actually uses the proxy.
async function socksFixture() {
  let count=0;const sockets=new Set();
  const server=net.createServer(socket=>{
    sockets.add(socket);socket.on('close',()=>sockets.delete(socket));socket.on('error',()=>{});
    let buffer=Buffer.alloc(0),stage=0;
    const read=data=>{
      buffer=Buffer.concat([buffer,data]);
      if(stage===0){if(buffer.length<2 || buffer.length<2+buffer[1])return;buffer=buffer.subarray(2+buffer[1]);socket.write(Buffer.from([5,0]));stage=1;}
      if(stage===1){
        if(buffer.length<5)return;let host,end;
        if(buffer[3]===1){end=8;if(buffer.length<end+2)return;host=[...buffer.subarray(4,8)].join('.');}
        else if(buffer[3]===3){end=5+buffer[4];if(buffer.length<end+2)return;host=buffer.subarray(5,end).toString();}
        else {socket.destroy();return;}
        const port=buffer.readUInt16BE(end),remaining=buffer.subarray(end+2);stage=2;count++;
        socket.removeListener('data',read);socket.pause();
        const upstream=net.connect(port,host,()=>{
          socket.write(Buffer.from([5,0,0,1,127,0,0,1,0,0]));if(remaining.length)upstream.write(remaining);
          socket.pipe(upstream);upstream.pipe(socket);socket.resume();
        });
        sockets.add(upstream);upstream.on('close',()=>sockets.delete(upstream));
        upstream.on('error',()=>socket.destroy());socket.on('close',()=>upstream.destroy());
      }
    };socket.on('data',read);
  });
  await new Promise(r=>server.listen(0,'127.0.0.1',r));
  return {port:server.address().port,count:()=>count,close:()=>{for(const s of sockets)s.destroy();server.close();}};
}
test('real Chromium: redirects, SPA, challenge, blank, HTTP error, timeout, failed resource, proxy failure',async()=>{
  const body='<h1>Fixture Login portal with enough visible text for readiness</h1><button>Login</button>';
  const server=http.createServer((req,res)=>{
    if(req.url==='/redirect'){res.writeHead(302,{Location:'/ok'});return res.end();}
    if(req.url==='/redirect403'){res.writeHead(302,{Location:'/403'});return res.end();}
    if(req.url==='/403'){res.writeHead(403);return res.end(body);}
    if(req.url==='/timeout')return;
    if(req.url==='/resource'){res.writeHead(500);return res.end();}
    res.setHeader('Content-Type','text/html');
    if(req.url==='/challenge')return res.end('<h1>Verify you are human - security check captcha</h1><button>Login</button>');
    if(req.url==='/blank')return res.end('<div id="app"></div>');
    if(req.url==='/spa')return res.end(`<script>setTimeout(()=>document.body.innerHTML=${JSON.stringify(body)},50)</script>`);
    res.end(body+'<img src="/resource"><script>fetch("/resource")</script>');
  });
  await new Promise(r=>server.listen(0,'127.0.0.1',r));
  const proxy=await socksFixture(),out=fs.mkdtempSync(path.join(os.tmpdir(),'xray-browse-'));
  const browser=await chromium.launch({headless:true,proxy:{server:`socks5://127.0.0.1:${proxy.port}`},args:['--disable-quic','--proxy-bypass-list=<-loopback>']});
  const url=`http://127.0.0.1:${server.address().port}`;
  try {
    const run=(p,i)=>visit(browser,{url:url+p,required:true,text:'Fixture Login',selector:'button'},i,out,{timeout:700,dwell:30});
    assert.equal((await run('/redirect',0)).ok,true);
    assert.equal((await run('/spa',1)).ok,true);
    for(const [i,p] of ['/403','/redirect403','/challenge','/blank','/timeout'].entries())assert.equal((await run(p,i+2)).ok,false,p);
    const cert=spawnSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',path.join(out,'key.pem'),'-out',path.join(out,'cert.pem'),'-days','1','-subj','/CN=localhost'],{encoding:'utf8'});
    assert.equal(cert.status,0,cert.stderr);
    const tls=https.createServer({key:fs.readFileSync(path.join(out,'key.pem')),cert:fs.readFileSync(path.join(out,'cert.pem'))},(req,res)=>res.end(body));
    await new Promise(r=>tls.listen(0,'127.0.0.1',r));
    try {
      const invalidTLS=await visit(browser,{url:`https://127.0.0.1:${tls.address().port}/`,required:true,text:'Fixture Login',selector:'button'},20,out,{timeout:1500,dwell:0});
      assert.equal(invalidTLS.ok,false);assert.match(invalidTLS.error,/CERT_/);
    } finally {tls.closeAllConnections();tls.close();}
    assert(proxy.count()>0,'Requests must traverse SOCKS');
    const bad=await browser.newContext({proxy:{server:'socks5://127.0.0.1:1'}});
    const page=await bad.newPage();await assert.rejects(page.goto(url,{timeout:1500}));await bad.close();
  } finally {await browser.close();proxy.close();server.closeAllConnections();server.close();fs.rmSync(out,{recursive:true,force:true});}
});
