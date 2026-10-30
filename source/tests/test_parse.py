import os,json,subprocess,pathlib,threading,http.server,tempfile
import argparse
parser=argparse.ArgumentParser()
parser.add_argument('--script', type=pathlib.Path, default=pathlib.Path(__file__).resolve().parents[1]/'SubnetResolve.sh')
args=parser.parse_args()
script=args.script.resolve()
workspace=tempfile.TemporaryDirectory(prefix='subnetresolve-test-')
root=pathlib.Path(workspace.name)
source=script.read_text()
helper=source.split("<<'SUBNET_PARSE_JS'\n",1)[1].split('\nSUBNET_PARSE_JS',1)[0]
(root/'extracted-parse.cjs').write_text(helper)
cache=pathlib.Path(os.environ.get('XDG_CACHE_HOME',str(pathlib.Path.home()/'.cache')))
runtime=os.environ.get('SUBNET_PLAYWRIGHT',str(cache/'SubnetResolve/playwright-1.64.1/node_modules/playwright'))
class Handler(http.server.BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def do_GET(self):
  port=self.server.server_port
  if self.path.startswith('/Start'):
   body=f'''<html><body style="height:8000px"><script>
fetch('http://api.localhost:{port}/data');
fetch('http://api.localhost:{port}/again');
setTimeout(()=>fetch('http://delayed.localhost:{port}/data'),500);
new WebSocket('ws://socket.localhost:{port}/ws');
addEventListener('scroll',()=>fetch('http://lazy.localhost:{port}/data'),{{once:true}});
</script><iframe src="http://frame.localhost:{port}/frame"></iframe></body></html>'''
  else:body='ok'
  self.send_response(403 if self.path.startswith('/Denied') else 200);self.send_header('Access-Control-Allow-Origin','*');self.send_header('Content-Type','text/html');self.end_headers();self.wfile.write(body.encode())
server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler);threading.Thread(target=server.serve_forever,daemon=True).start()
seed=f'http://site.localhost:{server.server_port}/Start?Case=YES'
(root/'parse-seeds.json').write_text(json.dumps([seed]))
env={**os.environ,'SUBNET_PLAYWRIGHT':runtime,'XDG_CACHE_HOME':str(cache)}
p=subprocess.run(['node',str(root/'extracted-parse.cjs'),str(root/'parse-seeds.json'),str(root/'parse-discovery.json'),str(root/'parse-progress')],env=env,capture_output=True,text=True,timeout=65)
assert p.returncode==0,(p.stdout,p.stderr)
d=json.loads((root/'parse-discovery.json').read_text());expected={'site.localhost','api.localhost','delayed.localhost','socket.localhost','frame.localhost','lazy.localhost'}
assert set(d['domains'])==expected,d
assert d['complete'] and not p.stdout
print('PASS real Chromium: JS, delayed fetch, dedup, iframe, WebSocket, scroll, URL path/case preserved',flush=True)
# Same browser through the full Bash entrypoint, with DNS/BGP mock executables.
bin=root/'parse-bin';bin.mkdir(exist_ok=True)
(bin/'curl').write_text('''#!/bin/bash
case "$*" in
 *check-dns*) printf '%s\\n' '{"ok":1,"request_id":"abc","permanent_link":"https://check-host.net/check-report/abc","nodes":{"n":["xx","Country","City","9.9.9.9","AS9"]}}';;
 *) printf '%s\\n' '{"n":[{"A":["1.1.1.1"]}]}';;
esac
''')
(bin/'nc').write_text('''#!/bin/bash
while IFS= read -r line; do printf '%s\\n' "$line" >> "$SENT"; [ "$line" = end ] && break; done
printf '%s\\n' '13335 | 1.1.1.1 | 1.1.1.0/24 | US | ARIN | 2020-01-01 | Cloudflare'
''')
for file in bin.iterdir():file.chmod(0o755)
env.update(PATH=str(bin)+':'+env['PATH'],SENT=str(root/'parse-sent'))
(root/'parse-sent').write_text('')
p=subprocess.run(['/bin/bash',str(script),'-parse','-4s',seed],env=env,text=True,capture_output=True,timeout=90)
assert p.returncode==0,p.stderr
r=json.loads(p.stdout);assert set(r)=={'ip','domain'} and r['domain']==['domain:'+h for h in sorted(expected)] and r['ip']==['1.1.1.0/24'],r
assert (root/'parse-sent').read_text().splitlines().count('1.1.1.1')==1
print('PASS full -parse -4s: one JSON, unique domain: entries, one unique IP sent to BGP for six domains',flush=True)
p=subprocess.run(['/bin/bash',str(script),'-parse','-vs',seed.replace('/Start?Case=YES','/Denied')],env=env,text=True,capture_output=True,timeout=65)
assert p.returncode==3,p.stderr
r=json.loads(p.stdout);assert r['domain']==['domain:site.localhost'] and not r['complete'] and r['discovery']['pages'][0]['errors']==['HTTP 403'] and 'domains' in r,r
assert 'HTTP 403' in p.stderr
print('PASS HTTP 403: partial status 3, discovery diagnostics, domain array and detailed DNS results coexist',flush=True)
server.shutdown()
workspace.cleanup()
