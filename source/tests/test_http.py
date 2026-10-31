"""Actual curl: redirects, final HTTP failures and bounded retry behavior."""
import argparse,collections,http.server,pathlib,subprocess,tempfile,threading,time
p=argparse.ArgumentParser();p.add_argument('--script',type=pathlib.Path,default=pathlib.Path(__file__).resolve().parents[1]/'SubnetResolve.sh');p.add_argument('--live-sites',action='store_true');args=p.parse_args()
source=args.script.read_text();functions=source[source.index('fetch_http() {'):source.index('\nget_json()')]
if args.live_sites:
 with tempfile.TemporaryDirectory() as root:
  for site in ('https://cloud.vk.com/','https://fornex.com/'):
   code='set -euo pipefail\nbatch=$1; verbose=0; stage=$2; stage_name=HTTP; progress(){ :; }; finish_progress(){ :; };\n'+functions+'\nfetch_http site "$2" > "$batch/body"\n'
   r=subprocess.run(['bash','-c',code,'probe',root,site],capture_output=True,text=True,timeout=9)
   print(r.stderr,end='');print('LIVE SITE',site,'result:', 'available' if r.returncode==0 else 'unavailable (see cause above)',flush=True)
 raise SystemExit(0)
counts=collections.Counter()
class Handler(http.server.BaseHTTPRequestHandler):
 def log_message(self,*a):pass
 def do_GET(self):
  path=self.path;counts[path]+=1
  redirect=None;status=200;body=b'ok'
  if path.startswith('/r/'):
   status=int(path.rsplit('/',1)[1]);redirect='/ok'
  elif path=='/cross':status=307;redirect=f'http://localhost:{self.server.server_port}/ok'
  elif path.startswith('/chain/'):
   n=int(path.rsplit('/',1)[1]);status=302;redirect='/chain/'+str(n-1) if n else '/ok'
  elif path=='/loop':status=302;redirect='/loop'
  elif path.startswith('/to/'):
   status=302;redirect=path[len('/to'):]
  elif path.startswith('/status/'):status=int(path.rsplit('/',1)[1])
  elif path in ('/slow','/slowbody'):
   if path=='/slow':time.sleep(2)
  elif path=='/challenge':status=403
  self.send_response(status)
  if redirect:self.send_header('Location',redirect)
  if path=='/challenge':self.send_header('cf-mitigated','challenge')
  self.end_headers()
  if path=='/slowbody':self.wfile.flush();time.sleep(2)
  try:self.wfile.write(body)
  except (BrokenPipeError,ConnectionResetError):pass
server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler);threading.Thread(target=server.serve_forever,daemon=True).start()
with tempfile.TemporaryDirectory() as root:
 code='set -euo pipefail\nbatch=$1; verbose=0; stage=local; stage_name=HTTP; progress(){ :; }; finish_progress(){ :; };\n'+functions+'\nfetch_http site "$2"\n'
 cases=[('/ok',True,None)]+[('/r/'+str(n),True,'Редирект') for n in (301,302,303,307,308)]+[('/cross',True,'http://localhost:'),('/chain/7',True,'Редирект'),('/loop',False,'50 редиректов'),('/to/status/403',False,'HTTP 403'),('/to/slow',False,'общий лимит')]+[('/status/'+str(n),False,'HTTP '+str(n)) for n in (403,404,429,500)]+[('/challenge',False,'Cloudflare challenge'),('/slow',False,'не начал HTTP-ответ'),('/slowbody',False,'Не завершена загрузка')]
 for route,success,reason in cases:
  before=counts[route]
  start=time.monotonic();r=subprocess.run(['bash','-c',code,'test',root,f'http://127.0.0.1:{server.server_port}'+route],capture_output=True,text=True,timeout=9);elapsed=time.monotonic()-start
  assert r.returncode==(0 if success else 1),(route,r.stderr)
  assert r.stdout==('ok' if success else ''),(route,r.stdout)
  assert counts[route]-before==(1 if success else (102 if route=='/loop' else 2)),(route,counts)
  assert 'curl:' not in r.stderr and '\x1b' not in r.stderr
  if reason:assert reason in r.stderr,(route,r.stderr)
  if route.startswith('/to/') or route=='/cross':assert 'конечный URL:' in r.stderr,(route,r.stderr)
  if 'slow' in route:assert 2.9<=elapsed<6,(elapsed,r.stderr)
  print('PASS real curl',route,'elapsed',round(elapsed,2),flush=True)
server.shutdown()
