"""Large workflow queues use bounded stdin batches and retain completed pages."""
import contextlib,errno,hashlib,io,json,subprocess,sys,tempfile
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'routing/scripts'))
from update_routing import collect_browser_pages
scanner=Path(__file__).resolve().parents[1]/'SubnetResolve.sh'
entries=[(f'h{i}.example',f'https://h{i}.example/Path?Case=YES') for i in range(504000)]
expected=hashlib.sha256((' '.join(url for _,url in entries)+' ').encode()).hexdigest()
seen=hashlib.sha256();count=0;calls=0

def mock_run(command,**kwargs):
    global count,calls
    assert len(command)==7 and command[-1]=='-v',command[-3:]
    assert not any(url in command for url in (entries[0][1],entries[-1][1]))
    assert sum(len(value.encode())+1 for value in command)<131072
    urls=kwargs['input'].split()
    assert 1<=len(urls)<=128
    count+=len(urls);calls+=1;seen.update((' '.join(urls)+' ').encode())
    return subprocess.CompletedProcess(command,0,'{"pages":[]}')
state={'pages':[],'domains':[],'complete':True}
with patch('update_routing.subprocess.run',side_effect=mock_run), contextlib.redirect_stdout(io.StringIO()):
    collect_browser_pages(scanner,entries,['-v'],10**12,state,None)
assert count==len(entries) and calls==(len(entries)+127)//128 and seen.hexdigest()==expected
print('PASS 504000 URLs: constant argv, stdin batches <=128, exact order/case and no lost entries')

with tempfile.TemporaryDirectory() as directory:
    evidence=Path(directory);state={'pages':[],'domains':[],'complete':True}
    first=[{'site':host,'domains':[host],'errors':[]} for host,_ in entries[:128]]
    with patch('update_routing.subprocess.run',side_effect=[
        subprocess.CompletedProcess([],0,json.dumps({'pages':first})),
        OSError(errno.E2BIG,'Argument list too long'),
    ]),contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()) as diagnostic:
        collect_browser_pages(scanner,entries[:257],[],10**12,state,evidence)
    saved=json.loads((evidence/'discovery.json').read_text())
    assert saved['pages']==first and not saved['complete'] and not state['complete']
    assert 'не удалось запустить процесс' in diagnostic.getvalue()
    assert len(diagnostic.getvalue())<1000
print('PASS completed pages survive process-start failure; clear bounded diagnostic and resumable checkpoint')

# Actual exec with >ARG_MAX-sized input: the payload must never enter argv.
with tempfile.TemporaryDirectory() as directory:
    fixture=Path(directory)/'scanner.sh'
    fixture.write_text('''batch=$(mktemp -d)
trap 'rm -rf "$batch"' EXIT
cat > "$batch/received"
printf '{"pages":[]}' > "$batch/discovery.json"
finish_progress() { :; }
unset inputs
stage_name='Этап 3/4: DNS'
''')
    state={'pages':[],'domains':[],'complete':True}
    with contextlib.redirect_stdout(io.StringIO()):
        collect_browser_pages(fixture,[('host.example','https://host.example/'+('x'*300000))],[],10**12,state,None)
    assert state['complete']
print('PASS real Bash process accepts 300KB input over stdin without exec argument overflow')
