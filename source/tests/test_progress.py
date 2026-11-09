"""Terminal/redirected UI regression: redirect flood and transient waits stay quiet."""
import argparse,os,pathlib,pty,select,subprocess,tempfile,time
p=argparse.ArgumentParser();p.add_argument('--script',type=pathlib.Path,default=pathlib.Path(__file__).resolve().parents[1]/'SubnetResolve.sh');args=p.parse_args();source=args.script.read_text()
finish=source[source.index('finish_progress() {'):source.index('\ndie()')]
progress=source[source.index('\nprogress() {'):source.index('\ncleanup() {')]
site=source[source.index('site_progress() {'):source.index('fetch_http() {')]
a=source.index('  drain_browser_messages() {');drain=source[a:source.index('\n  while kill',a)]
with tempfile.NamedTemporaryFile(mode='w') as log:
 log.write('[Этап 2/4: браузер] Редирект: mc.yandex.ru → mc.yandex.ru\n'*100)
 log.write('SUBNET_PAGE_DONE 1/2: beget.com; найдено доменов: 12\nSUBNET_PAGE_DONE 2/2: cloud.ru; найдено доменов: 22\n');log.flush()
 code='set -euo pipefail\nverbose=$2; started=$SECONDS; stage_name="Этап 2/4: браузер"; progress_active=0; browser_completed_index=""\n'+finish+progress+'\n'+site+drain+'''
exec 4< "$1"
progress 'Сбор доменов: загрузка и прокрутка'
drain_browser_messages
[ "$browser_completed_index" = 2/2 ]
# Same rendering path is used by API timeout/recovery.
stage_name='Этап 3/4: DNS'
progress 'тайм-аут API Check-Host; Ждём 5 с'
progress 'ожидание API Check-Host — повтор через 5 с'
progress 'тайм-аут API Check-Host; Ждём 10 с'
progress 'Домен 1/1: ответили 48/48 узлов'
finish_progress
'''
 for terminal in (False,True):
  for verbose in (0,1):
   if terminal:
    master,slave=pty.openpty();proc=subprocess.Popen(['bash','-c',code,'test',log.name,str(verbose)],stdout=subprocess.PIPE,stderr=slave);data=b'';deadline=time.monotonic()+10
    while time.monotonic()<deadline:
     ready=select.select([master],[],[],0.1)[0]
     if ready:
      try:part=os.read(master,4096)
      except OSError:break
      if not part:break
      data+=part
     elif proc.poll() is not None:break
    if proc.poll() is None:proc.kill()
    out=proc.communicate(timeout=2)[0]
    os.close(slave);os.close(master);err=data.decode()
   else:
    proc=subprocess.run(['bash','-c',code,'test',log.name,str(verbose)],capture_output=True,text=True,timeout=10);out=proc.stdout;err=proc.stderr
   assert proc.returncode==0 and not out,err
   assert err.count('найдено доменов: 12')==1 and err.count('найдено доменов: 22')==1,err
   assert 'SUBNET_PAGE_DONE' not in err and 'Ctrl+C' not in err and 'повторяем тот же запрос' not in err
   if verbose:assert err.count('Редирект:')==100 and 'Ждём' in err
   else:
    assert 'Редирект:' not in err and 'mc.yandex.ru' not in err
    assert err.count('\n')==(3 if terminal else 2),repr(err)
    if not terminal:assert 'Ждём' not in err and 'попытка' not in err
   print('PASS quiet browser/API progress: terminal='+str(terminal)+', verbose='+str(verbose),flush=True)
