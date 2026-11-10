import os,json,subprocess,pathlib,threading,http.server,tempfile
import argparse,base64,hashlib,shutil,time
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
parallel_starts = []
parallel_lock = threading.Lock()
first_wave = threading.Event()

class Handler(http.server.BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def do_GET(self):
  if self.headers.get('Upgrade','').lower()=='websocket':
   key=self.headers['Sec-WebSocket-Key']+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
   accept=base64.b64encode(hashlib.sha1(key.encode()).digest()).decode()
   self.send_response(101);self.send_header('Upgrade','websocket');self.send_header('Connection','Upgrade');self.send_header('Sec-WebSocket-Accept',accept);self.end_headers();return
  port=self.server.server_port
  if self.path.startswith('/Parallel/'):
   index = self.path.rsplit('/', 1)[-1]
   with parallel_lock:
    parallel_starts.append((index, time.monotonic()))
    if len(parallel_starts) == 4:
     first_wave.set()
   ready = first_wave.wait(8)
   self.send_response(403 if index == '1' else 200 if ready else 503)
   self.send_header('Content-Type', 'text/html')
   self.end_headers()
   self.wfile.write(f'<iframe src="http://resource{index}.localhost:{port}/frame"></iframe>'.encode())
   return
  if self.path.startswith('/Redirect'):
   self.send_response(307);self.send_header('Location',f'http://redirect.localhost:{port}/Hop?Case=YES');self.end_headers();return
  if self.path == '/Hop?Case=YES':
   self.send_response(302);self.send_header('Location',f'http://api.localhost:{port}/Start?Case=YES');self.end_headers();return
  if self.path == '/Start?Case=YES':
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
seed=f'http://site.localhost:{server.server_port}/Redirect?Case=YES'
(root/'parse-seeds.json').write_text(json.dumps([seed]))
env={**os.environ,'SUBNET_PLAYWRIGHT':runtime,'XDG_CACHE_HOME':str(cache),'SUBNET_VERBOSE':'1'}
p=subprocess.run(['node',str(root/'extracted-parse.cjs'),str(root/'parse-seeds.json'),str(root/'parse-discovery.json'),str(root/'parse-progress')],env=env,capture_output=True,text=True,timeout=65)
assert p.returncode==0,(p.stdout,p.stderr)
d=json.loads((root/'parse-discovery.json').read_text());expected={'site.localhost','redirect.localhost','api.localhost','delayed.localhost','socket.localhost','frame.localhost','lazy.localhost'}
assert set(d['domains'])==expected,d
assert d['complete'] and not p.stdout and 'Редирект: site.localhost → redirect.localhost' in p.stderr
print('PASS real Chromium: JS, delayed fetch, dedup, iframe, WebSocket, scroll, URL path/case preserved',flush=True)
# Four pages must reach the server before it releases the first response.
# The fifth must wait for a slot to finish collecting requests.
parallel_seeds = [f'http://site{i}.localhost:{server.server_port}/Parallel/{i}' for i in range(5)]
(root/'parse-seeds.json').write_text(json.dumps(parallel_seeds))
p = subprocess.run(
 ['node', str(root/'extracted-parse.cjs'), str(root/'parse-seeds.json'),
  str(root/'parallel-discovery.json'), str(root/'parse-progress')],
 env=env, capture_output=True, text=True, timeout=50)
assert p.returncode == 0 and not p.stdout, (p.stdout, p.stderr)
assert {i for i, _ in parallel_starts[:4]} == {'0', '1', '2', '3'}, parallel_starts
assert len(parallel_starts) == 5 and parallel_starts[4][0] == '4', parallel_starts
assert parallel_starts[4][1] - parallel_starts[3][1] >= 8, parallel_starts
parallel = json.loads((root/'parallel-discovery.json').read_text())
assert len(parallel['pages']) == 5 and not parallel['complete'], parallel
for i, page in enumerate(parallel['pages']):
 assert page['site'] == f'site{i}.localhost', parallel
 assert set(page['domains']) == {f'site{i}.localhost', f'resource{i}.localhost'}, page
 assert bool(page['errors']) == (i == 1), page
assert 'отказал' in parallel['pages'][1]['errors'][0], parallel
assert set(parallel['domains']) == {host for page in parallel['pages'] for host in page['domains']}
print('PASS real Chromium: four concurrent sites, fifth waits, isolated domains and failure, stable output order', flush=True)
# Same browser through the full Bash entrypoint, with DNS/BGP mock executables.
bin=root/'parse-bin';bin.mkdir(exist_ok=True)
real_curl=shutil.which('curl')
(bin/'curl').write_text('''#!/bin/bash
case "$*" in *check-host.net*) ;; *) exec REAL_CURL "$@" ;; esac
case "$*" in
 *check-dns*) printf '%s\\n' '{"ok":1,"request_id":"abc","permanent_link":"https://check-host.net/check-report/abc","nodes":{"n":["xx","Country","City","9.9.9.9","AS9"]}}';;
 *) printf '%s\\n' '{"n":[{"A":["1.1.1.1"]}]}';;
esac
'''.replace('REAL_CURL',__import__('shlex').quote(real_curl)))
(bin/'nc').write_text('''#!/bin/bash
while IFS= read -r line; do printf '%s\\n' "$line" >> "$SENT"; [ "$line" = end ] && break; done
printf '%s\\n' '13335 | 1.1.1.1 | 1.1.1.0/24 | US | ARIN | 2020-01-01 | Cloudflare'
''')
for file in bin.iterdir():file.chmod(0o755)
env.update(PATH=str(bin)+':'+env['PATH'],SENT=str(root/'parse-sent'))
(root/'parse-sent').write_text('')
p=subprocess.run(['/bin/bash',str(script),'-parse','-4s',seed],env=env,text=True,capture_output=True,timeout=90)
assert p.returncode==0 and 'Редирект: site.localhost → redirect.localhost' in p.stderr,p.stderr
for line in p.stderr.splitlines():
 if 'Редирект:' in line:assert 'http://' not in line and '?Case=' not in line,line
assert '[Этап 2/4: браузер] Редирект:' not in p.stderr and 'SUBNET_PAGE_DONE' not in p.stderr,p.stderr
assert p.stderr.count('Сбор доменов: 1/1: site.localhost; найдено доменов:')==1,p.stderr
r=json.loads(p.stdout);assert set(r)=={'ip','domain'} and r['domain']==['domain:'+h for h in sorted(expected)] and r['ip']==['1.1.1.0/24'],r
transactions=(root/'parse-sent').read_text().split('end\n');assert transactions[0].splitlines().count('1.1.1.1')==1 and transactions[1].splitlines().count('1.1.1.1')==1 and len(transactions)==3
print('PASS full -parse -4s: one JSON, unique domain: entries, one unique IP sent to BGP for all discovered domains',flush=True)
# Check the published domain format through the routing generator. The
# intermediate redirect host appears only in Location, never in page resources.
sites=root/'sites.txt'
sites.write_text(seed+'\n')
generator=pathlib.Path(__file__).resolve().parents[1]/'routing/update_routing.py'
fixture_scanner=root/'routing-scanner.sh'
fixture_scanner.write_text('#!/bin/bash\nunset SUBNET_BGP_OBSERVATIONS\nexec bash '
                           +__import__('shlex').quote(str(script))+' "$@"\n')
routing_run=subprocess.run(
 ['python3',str(generator),'--sites',str(sites),'--scanner',str(fixture_scanner),'--output',str(root/'IP.json')],
 env=env,text=True,capture_output=True,timeout=90)
assert routing_run.returncode==0,routing_run.stderr
published=json.loads((root/'domains.json').read_text())
assert published=={'rules':[{'ruleTag':'site.localhost',
                             'domain':['domain:'+host for host in sorted(expected)]}]},published
print('PASS domains.json retains the intermediate and final redirect hosts under the source site',flush=True)
p=subprocess.run(['/bin/bash',str(script),'-parse','-vs',seed.replace('/Redirect?Case=YES','/Denied')],env=env,text=True,capture_output=True,timeout=65)
assert p.returncode==3,p.stderr
r=json.loads(p.stdout);assert r['domain']==['domain:site.localhost'] and r['domains'][0]['results'][0]['prefix']=='1.1.1.0/24' and not r['complete'] and 'отказал' in r['discovery']['pages'][0]['errors'][0] and 'domains' in r,r
assert 'отказал' in p.stderr and 'Ресурсы страницы не загружены' in p.stderr and 'код выхода' not in p.stderr and 'код результата' not in p.stderr
print('PASS HTTP 403: curl skips Chromium, retains domain and still resolves its prefix',flush=True)
server.shutdown()
if os.environ.get('TEST_ARTIFACTS'):
 destination=pathlib.Path(os.environ['TEST_ARTIFACTS']);destination.mkdir(parents=True,exist_ok=True)
 (destination/'discovery.json').write_text(json.dumps(d,ensure_ascii=False,indent=2))
 (destination/'denied-result.json').write_text(json.dumps(r,ensure_ascii=False,indent=2))
 (destination/'denied-stderr.txt').write_text(p.stderr)
 (destination/'bgp-request.txt').write_text((root/'parse-sent').read_text())
workspace.cleanup()
