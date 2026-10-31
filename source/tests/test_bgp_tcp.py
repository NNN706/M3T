"""Real loopback TCP WHOIS: delayed replies, streaming, batching 1339 IPs."""
import argparse,ipaddress,json,os,pathlib,shlex,shutil,socketserver,subprocess,tempfile,threading,time
p=argparse.ArgumentParser();p.add_argument('--script',type=pathlib.Path,default=pathlib.Path(__file__).resolve().parents[1]/'SubnetResolve.sh');args=p.parse_args();source=args.script.read_text();helpers=source[source.index('bgp_state() {'):source.index('\n# Optional browser')]
setup='''set -euo pipefail
batch=$1; stage_name=BGP; stage=loopback; verbose=0; ncpid=''; bgp_writer_pid=''
progress(){ :; }
cleanup(){ for pid in "$ncpid" "$bgp_writer_pid"; do if [ -n "$pid" ]; then kill "$pid" 2>/dev/null || :; wait "$pid" 2>/dev/null || :; fi; done; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
'''
code=setup+helpers+'\nrc=0\nbgp_exchange "$batch/ips" "$batch/result" || rc=$?\ncat "$batch/bgp-state.json"\nexit "$rc"\n'
class Server(socketserver.ThreadingTCPServer):
 allow_reuse_address=True;daemon_threads=True;block_on_close=False
class Handler(socketserver.StreamRequestHandler):
 def handle(self):
  ips=[]
  while True:
   line=self.rfile.readline().decode().strip()
   if not line:return
   if line=='end':break
   if line not in ('begin','verbose'):ips.append(line)
  with self.server.lock:
   self.server.calls.append(ips);number=len(self.server.calls);mode=self.server.mode
  def send(ip):
   row='64500 | '+ip+' | '+ip.rsplit('.',1)[0]+'.0/24 | ZZ | TEST | 2020-01-01 | Fixture\n'
   self.wfile.write(row.encode());self.wfile.flush()
  try:
   if mode in ('delayed','large') and number==1:time.sleep(2)
   if mode=='incomplete':
    for ip in ips[:-1]:send(ip)
    return
   for ip in ips:
    if mode=='streaming':time.sleep(6)
    send(ip)
   # Keep the connection open: client must stop after all requested rows arrive.
   time.sleep(15)
  except (BrokenPipeError,ConnectionResetError):pass
server=Server(('127.0.0.1',0),Handler);server.lock=threading.Lock();server.calls=[];server.mode='';threading.Thread(target=server.serve_forever,daemon=True).start()
real_nc=shutil.which('nc');assert real_nc,'nc is required for the real TCP integration test'
evidence=[]
with tempfile.TemporaryDirectory(prefix='bgp-tcp-') as directory:
 root=pathlib.Path(directory);bin=root/'bin';bin.mkdir();wrapper=bin/'nc';wrapper.write_text('#!/bin/sh\nexec '+shlex.quote(real_nc)+' -w 10 127.0.0.1 "$BGP_TEST_PORT"\n');wrapper.chmod(0o755)
 for mode,count in (('delayed',3),('streaming',2),('large',1339),('incomplete',205)):
  server.mode=mode;server.calls=[]
  ips=[str(ipaddress.IPv4Address(int(ipaddress.IPv4Address('11.0.0.1'))+i)) for i in range(count)]
  (root/'ips').write_text('\n'.join(ips)+'\n')
  start=time.monotonic();proc=subprocess.run(['bash','-c',code,'test',directory],env={**os.environ,'PATH':str(bin)+':'+os.environ['PATH'],'BGP_TEST_PORT':str(server.server_address[1])},capture_output=True,text=True,timeout=45);elapsed=time.monotonic()-start
  state=json.loads(proc.stdout);calls=server.calls.copy()
  assert all(0<len(c)<=100 for c in calls),(mode,[len(c) for c in calls])
  assert proc.returncode==(1 if mode=='incomplete' else 0),(mode,proc.stderr,state)
  if mode=='incomplete':
   assert [len(c) for c in calls]==[100,1,100,1,5,1],calls
   assert len(state['routes'])==202 and len(state['errors'])==3,state
  else:
   assert len(state['routes'])==count and state['pending']==[] and state['errors']==[],(mode,state)
   assert len(calls)==((count+99)//100),(mode,calls)
   assert len({ip for call in calls for ip in call})==count
  if mode=='delayed':assert 2<=elapsed<7,elapsed
  if mode=='streaming':assert 12<=elapsed<20,elapsed
  evidence.append({'mode':mode,'ip_count':count,'batch_sizes':[len(c) for c in calls],'routes':len(state['routes']),'errors':len(state['errors']),'elapsed':round(elapsed,3)})
  print('PASS real TCP BGP',mode,'IPs='+str(count),'batches='+str(len(calls)),'elapsed='+str(round(elapsed,2)),flush=True)
server.shutdown();server.server_close()
if os.environ.get('TEST_ARTIFACTS'):
 dest=pathlib.Path(os.environ['TEST_ARTIFACTS']);dest.mkdir(parents=True,exist_ok=True);(dest/'bgp-tcp.json').write_text(json.dumps(evidence,indent=2))
