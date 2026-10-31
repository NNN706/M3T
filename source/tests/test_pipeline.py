"""Deterministic full-entrypoint failure matrix; real browser covered by test_parse.py."""
import argparse, collections, json, os, pathlib, subprocess, tempfile
p=argparse.ArgumentParser();p.add_argument('--script',type=pathlib.Path,default=pathlib.Path(__file__).resolve().parents[1]/'SubnetResolve.sh');args=p.parse_args()
script=args.script.resolve()
MOCK=r'''#!/usr/bin/env python3
import sys,os,json,pathlib,urllib.parse
args=sys.argv[1:];name=pathlib.Path(sys.argv[0]).name;mode=os.environ['CASE'];trace=pathlib.Path(os.environ['TRACE'])
def log(phase,domain=''):
 with trace.open('a') as f:f.write(json.dumps([phase,domain])+'\n')
def check(host):return {'ok':1,'request_id':host.encode().hex(),'permanent_link':'https://check-host.net/check-report/abc','nodes':{'n':['xx','Country','City','9.9.9.9','AS9']}}
if name=='node':
 if '-e' in args or os.environ.get('SUBNET_PROBE')=='1':sys.exit(0)
 seeds=json.loads(pathlib.Path(args[1]).read_text());domains=sorted({urllib.parse.urlsplit(s).hostname for s in seeds})
 for d in domains:log('browser',d)
 pathlib.Path(args[2]).write_text(json.dumps({'domains':domains,'pages':[{'site':d,'domains':[d],'errors':[]} for d in domains],'complete':True}));sys.exit(0)
if name=='curl':
 assert args[args.index('--max-time')+1]=='1.5' and args[args.index('--connect-timeout')+1]=='1.5'
 url=args[-1]
 if 'check-host.net/check-dns' in url:
  host=next(a[5:] for a in args if a.startswith('host='));phase='health' if host=='https://check-host.net' else 'dns';log(phase,host)
  if phase=='health':
   assert 'max_nodes=3' in args
   if mode=='health':print('curl: (28) Connection timed out',file=sys.stderr);sys.exit(28)
   if mode=='retry' and trace.read_text().count('"health"')==1:sys.exit(7)
  if phase=='dns' and mode=='dns' and host.startswith('bad'):print('{}');sys.exit(0)
  print(json.dumps(check(host)))
 elif 'check-host.net/check-result/' in url:
  host=bytes.fromhex(url.rsplit('/',1)[1]).decode();log('result',host)
  if mode=='result' and host.startswith('bad'):print('not json');sys.exit(0)
  if mode=='empty' and host.startswith('bad'):print(json.dumps({'n':[None,{'message':'No A records'}]}))
  else:print(json.dumps({'n':[{'A':['3.3.3.3' if host.startswith('bad') else '2.2.2.2']}]}))
 else:
  host=urllib.parse.urlsplit(url).hostname;log('site',host)
  if mode=='site' and host.startswith('bad'):print('curl: (22) The requested URL returned error: 503',file=sys.stderr);sys.exit(22)
  print('ok')
elif name=='nc':
 ips=[]
 for line in sys.stdin:
  line=line.strip()
  if line=='end':break
  if line not in ('begin','verbose'):ips.append(line)
 phase='bgp-health' if ips==['1.1.1.1'] else 'bulk';log(phase,ips)
 if mode=='bgp-health' and phase=='bgp-health':print('invalid response');sys.exit(0)
 for ip in ips:
  if mode=='bgp' and ip=='3.3.3.3':continue
  print('13335 | '+ip+' | '+ip.rsplit('.',1)[0]+'.0/24 | US | ARIN | 2020-01-01 | Test')
'''
with tempfile.TemporaryDirectory(prefix='subnet-pipeline-') as directory:
 root=pathlib.Path(directory);bin=root/'bin';bin.mkdir()
 for name in ('curl','nc','node'):
  f=bin/name;f.write_text(MOCK);f.chmod(0o755)
 evidence=[]
 def run(mode,hosts,parse=False):
  trace=root/'trace';trace.write_text('')
  env={**os.environ,'PATH':str(bin)+':'+os.environ['PATH'],'CASE':mode,'TRACE':str(trace),'XDG_CACHE_HOME':str(root/'cache')}
  result=subprocess.run(['bash',str(script),*(['-parse'] if parse else []),'-4sv',*hosts],capture_output=True,text=True,env=env,timeout=30)
  events=[json.loads(s) for s in trace.read_text().splitlines()];phases=[e[0] for e in events]
  assert 'HTTPcurl' not in result.stderr and 'curl: (' not in result.stderr,result.stderr
  assert 'код выхода' not in result.stderr and 'код результата' not in result.stderr
  assert '[Этап ' in result.stderr
  evidence.append({'mode':mode,'hosts':hosts,'status':result.returncode,'events':events,'stderr':result.stderr})
  return result,events,phases
 combinations=[['good1.example','good2.example'],['good1.example','bad1.example'],['bad1.example','good1.example'],['bad1.example','bad2.example']]
 for mode in ('site','dns','result','empty','bgp'):
  for hosts in combinations:
   result,events,phases=run(mode,hosts,parse=mode=='site')
   good=[h for h in hosts if h.startswith('good')];bad=[h for h in hosts if h.startswith('bad')]
   assert result.returncode==(3 if bad else 0),(mode,hosts,result.stderr)
   output=json.loads(result.stdout)
   assert output['ip']==(['2.2.2.0/24'] if good else []),(mode,hosts,output)
   if mode=='site':
    assert output['domain']==['domain:'+h for h in sorted(good)]
    assert [d for phase,d in events if phase=='browser']==sorted(good)
    assert phases.count('site')==len(good)+2*len(bad)
    if good:assert max(i for i,x in enumerate(phases) if x=='site')<phases.index('browser')<phases.index('health')
    else:assert set(phases)=={'site'}
   if mode=='dns':
    for h in bad:assert events.count(['dns',h])==2 and ['result',h] not in events
   if mode=='result':
    for h in bad:assert events.count(['result',h])==2
   if 'health' in phases:assert phases.index('health')<phases.index('dns')
   if 'bulk' in phases:
    assert max(i for i,x in enumerate(phases) if x=='result')<phases.index('bgp-health')<phases.index('bulk')
    assert phases.count('bulk')==(2 if mode=='bgp' and bad else 1)
    for phase,ips in events:
     if phase=='bulk':assert len(ips)==len(set(ips)) and ('3.3.3.3' in ips)==(mode=='bgp' and bool(bad))
   else:assert not good
   print('PASS',mode,','.join(hosts),flush=True)
 for mode in ('health','bgp-health'):
  result,events,phases=run(mode,combinations[0])
  assert result.returncode==1 and not result.stdout,(mode,result.stderr)
  assert phases.count(mode)==2
  if mode=='health':assert phases==['health','health'] and '1,5 секунды' in result.stderr
  else:assert 'bulk' not in phases
  print('PASS shared service unavailable:',mode,flush=True)
 result,events,phases=run('retry',combinations[0]);assert result.returncode==0 and phases.count('health')==2,result.stderr
 print('PASS first attempt fails, second succeeds; duplicate IP sent once',flush=True)
 if os.environ.get('TEST_ARTIFACTS'):
  dest=pathlib.Path(os.environ['TEST_ARTIFACTS']);dest.mkdir(parents=True,exist_ok=True);(dest/'pipeline.json').write_text(json.dumps(evidence,ensure_ascii=False,indent=2))
