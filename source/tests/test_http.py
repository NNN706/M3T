import pathlib,tempfile,threading,http.server,subprocess,time,collections
import argparse
p=argparse.ArgumentParser();p.add_argument('--script',type=pathlib.Path,default=pathlib.Path(__file__).resolve().parents[1]/'SubnetResolve.sh');args=p.parse_args()
source=args.script.read_text()
functions=source[source.index('fetch_http() {'):source.index('\nget_json()')]
counts=collections.Counter()
class Handler(http.server.BaseHTTPRequestHandler):
 def log_message(self,*a):pass
 def do_GET(self):
  counts[self.path]+=1
  if self.path=='/slow':time.sleep(2)
  self.send_response(503 if self.path=='/bad' else 200);self.end_headers()
  try:self.wfile.write(b'ok')
  except BrokenPipeError:pass
server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler);threading.Thread(target=server.serve_forever,daemon=True).start()
with tempfile.TemporaryDirectory() as root:
 for route,wanted in [('ok',1),('bad',2),('slow',2)]:
  code='set -euo pipefail\nbatch=$1; verbose=0; stage=local; stage_name=HTTP; progress(){ :; }; finish_progress(){ :; };\n'+functions+'\nfetch_http site "$2"\n'
  start=time.monotonic();r=subprocess.run(['bash','-c',code,'test',root,f'http://127.0.0.1:{server.server_port}/{route}'],capture_output=True,text=True,timeout=8);elapsed=time.monotonic()-start
  assert counts['/'+route]==wanted and r.returncode==(0 if route=='ok' else 1),(route,r.stderr,counts)
  assert 'curl:' not in r.stderr
  if route=='slow':assert 2.9<=elapsed<5 and '1,5 секунды' in r.stderr,(elapsed,r.stderr)
  print('PASS real curl',route,'requests',wanted,'elapsed',round(elapsed,2))
server.shutdown()
