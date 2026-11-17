"""Real Bash entrypoint: country selection, public IPs, API fallback and provenance."""
import ast,json,os,subprocess,tempfile
from pathlib import Path
root=Path(__file__).resolve().parents[1]
a=ast.parse(Path(__file__).with_name('test_pipeline.py').read_text())
mock=next(ast.literal_eval(n.value) for n in a.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='MOCK' for t in n.targets))
mock=mock.replace("  host=next(a[5:]", "  assert 'node=n' in args and 'node=ir1.node.check-host.net' not in args\n  host=next(a[5:]")
mock=mock.replace("  if phase=='dns' and mode=='dns'", "  if phase=='dns' and mode in ('fallback','fallback-empty','fallback-timeout','fallback-private') and host.startswith('bad'):\n   pathlib.Path(args[args.index('-D')+1]).write_text('HTTP/2 429\\r\\nRetry-After: 0\\r\\n\\r\\n');sys.exit(22)\n  if phase=='dns' and mode=='dns'")
mock=mock.replace("  print(json.dumps(check(host)))", "  data=check(host);data['nodes']['ir1.node.check-host.net']=['ir','Iran','Tehran','1.2.3.4','AS1'];print(json.dumps(data))")
mock=mock.replace("  if mode=='result' and", "  if mode in ('private','private-only'):\n   print(json.dumps({'n':[{'A':['10.10.34.35','10.10.34.36']+(['2.2.2.2'] if mode=='private' else [])}], 'ir1.node.check-host.net':[{'A':['9.9.9.9']}]}));sys.exit(0)\n  if mode=='result' and")
mock=mock.replace("elif name=='dig':\n", "elif name=='dig':\n log('yandex',args)\n if mode=='fallback-timeout':sys.exit(9)\n if mode in ('fallback','fallback-private'):\n  print(';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1')\n  print('bad.example. 60 IN A '+('10.10.34.35' if mode=='fallback-private' else '3.3.3.3'));sys.exit(0)\n")
with tempfile.TemporaryDirectory() as directory:
 p=Path(directory);b=p/'bin';b.mkdir();trace=p/'trace'
 for name in ('curl','nc','dig'):
  f=b/name;f.write_text(mock);f.chmod(0o755)
 for mode in ('private','private-only','fallback','fallback-empty','fallback-timeout','fallback-private'):
  trace.write_text('')
  env={**os.environ,'PATH':str(b)+':'+os.environ['PATH'],'CASE':mode,'TRACE':str(trace),'XDG_CACHE_HOME':str(p/'cache')}
  proc=subprocess.run(['bash',str(root/'SubnetResolve.sh'),'-sv','good.example','bad.example'],env=env,capture_output=True,text=True,timeout=40)
  assert proc.returncode in (0,3),(mode,proc.stderr)
  d=json.loads(proc.stdout);rows={r['domain']:r for r in d['domains']}
  events=[json.loads(s) for s in trace.read_text().splitlines()]
  for phase,ips in events:
   if phase=='bulk':assert not any(ip.startswith('10.') or ip=='9.9.9.9' for ip in ips)
  if mode=='private':assert proc.returncode==0 and all(r['complete'] for r in rows.values())
  elif mode=='private-only':assert proc.returncode==3 and not any(phase=='bulk' for phase,_ in events)
  elif mode=='fallback':
   assert proc.returncode==0,proc.stderr
   assert rows['bad.example']['dns_fallback']['provider']=='yandex'
   assert rows['bad.example']['dns_fallback']['resolver']=='77.88.8.8'
   assert '429' in rows['bad.example']['dns_fallback']['reason']
   assert rows['bad.example']['results'][0]['ips']==['3.3.3.3']
   assert rows['good.example']['complete'] and 'dns_fallback' not in rows['good.example']
  else:
   assert proc.returncode==3 and rows['good.example']['complete'] and not rows['bad.example']['complete']
  if mode.startswith('fallback'):
   attempts=[x for phase,x in events if phase=='yandex']
   assert len(attempts)==(2 if mode=='fallback-timeout' else 1)
  print('PASS',mode)
 # Old checkpoints must not bypass the country/public-IP policy.
 host='good.example';trace.write_text('')
 checkpoint=p/'old-dns.json'
 nodes={'n':['xx','Country','City','9.9.9.9','AS9'],'ir1.node.check-host.net':['ir','Iran','Tehran','1.2.3.4','AS1']}
 rows=[{'node':'n','ips':['10.10.34.35','2.2.2.2'],'response':{}},
       {'node':'ir1.node.check-host.net','ips':['9.9.9.9'],'response':{}}]
 checkpoint.write_text(json.dumps({'version':1,'services':[host],'discovery':None,'whois':'',
  'dns':[{'domain':host,'check':{'nodes':nodes,'permanent_link':None},'nodes':rows,
          'observations':[{'ip':ip,'node':row['node']} for row in rows for ip in row['ips']]}]}))
 env={**os.environ,'PATH':str(b)+':'+os.environ['PATH'],'CASE':'ok','TRACE':str(trace),'XDG_CACHE_HOME':str(p/'cache')}
 proc=subprocess.run(['bash',str(root/'SubnetResolve.sh'),'-4s','--resume-bgp',str(checkpoint)],env=env,capture_output=True,text=True,timeout=20)
 assert proc.returncode==0,proc.stderr
 assert json.loads(proc.stdout)=={'ip':['2.2.2.0/24']}
 events=[json.loads(s) for s in trace.read_text().splitlines()]
 assert [ips for phase,ips in events if phase=='bulk']==[['2.2.2.2']]
 assert not any(phase in ('dns','yandex','health') for phase,_ in events)
 print('PASS old checkpoint removes Iranian observations and non-public IPv4 before WHOIS')
 trace.write_text('');env['CASE']='fallback'
 proc=subprocess.run(['bash',str(root/'SubnetResolve.sh'),'-4s','bad.example'],env=env,capture_output=True,text=True,timeout=30)
 assert proc.returncode==0 and json.loads(proc.stdout)=={'ip':['3.3.3.0/24']},proc.stderr
 print('PASS successful Yandex fallback preserves exact -4 JSON interface')
