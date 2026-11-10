"""Full script: outage recovery, unchanged-domain resume, final empty DNS replies."""
import argparse,ast,json,os,pathlib,signal,subprocess,tempfile
p=argparse.ArgumentParser();p.add_argument('--script',type=pathlib.Path,default=pathlib.Path(__file__).resolve().parents[1]/'SubnetResolve.sh');args=p.parse_args();script=args.script.resolve()
module=ast.parse(pathlib.Path(__file__).with_name('test_pipeline.py').read_text())
mock=next(ast.literal_eval(n.value) for n in module.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='MOCK' for t in n.targets))
mock=mock.replace("  if phase=='health':", """  count=sum(1 for x in trace.read_text().splitlines() if json.loads(x)==[phase,host])
  if (mode in ('wait-health','wait-long','wait-forever') and phase=='health') or (mode=='wait-dns' and phase=='dns' and host=='good2.example'):
   if mode=='wait-forever' or count <= (8 if mode=='wait-long' else 2):sys.exit(28)
  if phase=='health':""")
mock=mock.replace("  print(json.dumps(check(host)))", """  info=check(host)
  if mode in ('pending','wait-budget') and phase=='dns':info['nodes']['late']=['xx','Country','City','8.8.8.8','AS8']
  if mode=='four-nodes' and phase=='dns':info['nodes']={f'n{i}':info['nodes']['n'] for i in range(48)}
  print(json.dumps(info))""")
mock=mock.replace("  if mode=='result'", """  count=sum(1 for x in trace.read_text().splitlines() if json.loads(x)==['result',host])
  if mode=='wait-result' and host=='good2.example' and count<=2:sys.exit(28)
  if mode=='wait-budget' and count in (2,3):sys.exit(28)
  if mode in ('pending','wait-budget'):
   print(json.dumps({'n':[{'A':[] if count==1 else ['9.9.9.9']}], 'late':None if count in ((1,4) if mode=='wait-budget' else (1,)) else [{'A':['2.2.2.2']}]}));sys.exit(0)
  if mode=='four-nodes':
   replies={f'n{i}':[{'A':['2.2.2.2']}] if i<4 else [None,{'message':'Connect timeout'}] if i%2 else [{'A':[]}] for i in range(48)}
   replies['n47']=None
   print(json.dumps(replies));sys.exit(0)
  if mode=='node-timeout':
   print(json.dumps({'n':[None,{'message':'Connect timeout'}]}));sys.exit(0)
  if mode=='result'""")
with tempfile.TemporaryDirectory(prefix='subnet-wait-') as directory:
 root=pathlib.Path(directory);bin=root/'bin';bin.mkdir()
 for name in ('curl','nc','node'):
  f=bin/name;f.write_text(mock);f.chmod(0o755)
 sleep=bin/'sleep';sleep.write_text('#!/bin/bash\nif [ \"$1\" = 0.1 ]; then exec /bin/sleep 0.05; fi\nprintf "%s\\n" "$1" >> "$WAIT_TRACE"\n');sleep.chmod(0o755)
 trace=root/'trace';waits=root/'waits';evidence=[]
 def run(mode,hosts,flags='-4sv',real_sleep=False):
  trace.write_text('');waits.write_text('')
  env={**os.environ,'PATH':str(bin)+':'+os.environ['PATH'],'CASE':mode,'TRACE':str(trace),'WAIT_TRACE':str(waits),'XDG_CACHE_HOME':str(root/'cache')}
  if mode=='wait-budget':
   clock=root/'clock.sh';clock.write_text('sleep() { if [ "$1" = 1 ]; then SECONDS=$((SECONDS + 20)); else /bin/sleep 0.05; fi; }\n');env['BASH_ENV']=str(clock)
  if real_sleep and sleep.exists():sleep.unlink()
  return subprocess.Popen(['bash',str(script),flags,*hosts],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True)
 for mode in ('wait-health','wait-dns','wait-result','wait-long'):
  proc=run(mode,['good1.example','good2.example']);out,err=proc.communicate(timeout=25)
  assert proc.returncode==0 and json.loads(out)=={'ip':['2.2.2.0/24']},(mode,out,err)
  events=[json.loads(x) for x in trace.read_text().splitlines()]
  assert 'Ждём 5 с' in err and 'Check-Host снова отвечает' in err,(mode,err)
  assert 'обе попытки не удались' not in err
  for host in ('good1.example','good2.example'):
   assert events.count(['dns',host])==(3 if mode=='wait-dns' and host=='good2.example' else 1),(mode,events)
  if mode=='wait-result':assert events.count(['result','good2.example'])==3
  assert waits.read_text().splitlines().count('1')==(65 if mode=='wait-long' else 5),(mode,waits.read_text())
  if mode=='wait-long':
   assert all('Ждём '+str(n)+' с' in err for n in (5,10,20,30)),err
  evidence.append({'mode':mode,'events':events,'stderr':err});print('PASS wait/recover',mode,flush=True)
 for mode in ('empty','node-timeout','pending','wait-budget'):
  proc=run(mode,['bad1.example'],'-sv');out,err=proc.communicate(timeout=25);result=json.loads(out)
  assert proc.returncode==(0 if mode in ('pending','wait-budget') else 3),(mode,out,err)
  assert result['complete']==(mode in ('pending','wait-budget')),result
  events=[json.loads(x) for x in trace.read_text().splitlines()]
  assert events.count(['dns','bad1.example'])==1
  assert events.count(['result','bad1.example'])==(5 if mode=='wait-budget' else (2 if mode=='pending' else 1)),(mode,events)
  if mode in ('pending','wait-budget'):
   assert result['results'][0]['ips']==['2.2.2.2'],result
   assert result['errors'][0]['check_host']=='n',result
  else:assert result['results']==[]
  assert ('Ждём' in err)==(mode=='wait-budget')
  print('PASS final node response: no restart/replacement',mode,flush=True)
 for flags in ('-s','-sv'):
  proc=run('four-nodes',['geo.example'],flags);out,err=proc.communicate(timeout=25)
  result=json.loads(out)
  assert proc.returncode==0 and result['complete'],(out,err)
  assert result['results'][0]['prefix']=='2.2.2.0/24',result
  assert result['results'][0]['check_host']==['n0','n1','n2','n3'],result
  assert len(result['errors'])==44,result
  assert ('Connect timeout' in err)==(flags=='-sv'),err
  assert 'Проверка завершена с ограничениями' not in err,err
 print('PASS four nodes with IPv4 out of 48 are enough for success',flush=True)
 proc=run('wait-health',['good1.example','good2.example'],'-4s')
 out,err=proc.communicate(timeout=25)
 assert proc.returncode==0 and json.loads(out)=={'ip':['2.2.2.0/24']},err
 assert 'Ждём' not in err and 'снова отвечает' not in err and 'Ctrl+C' not in err,err
 print('PASS quiet redirected output: no transient API wait/recovery lines',flush=True)
 for sig,status in ((signal.SIGINT,130),(signal.SIGTERM,143)):
  proc=run('wait-forever',['good1.example'],'-4sv',real_sleep=True)
  try:
   proc.communicate(timeout=1.5);raise AssertionError('timeout must wait rather than exit')
  except subprocess.TimeoutExpired:
   os.killpg(proc.pid,sig);out,err=proc.communicate(timeout=3)
   assert proc.returncode in (status,-sig) and not out and 'Ждём' in err,(proc.returncode,err)
  print('PASS persistent outage waits; signal stops promptly',sig,flush=True)
 if os.environ.get('TEST_ARTIFACTS'):
  dest=pathlib.Path(os.environ['TEST_ARTIFACTS']);dest.mkdir(parents=True,exist_ok=True);(dest/'wait.json').write_text(json.dumps(evidence,ensure_ascii=False,indent=2))
