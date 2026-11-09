"""Real local Git remote verifies publication when test advances during a scan."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('publish', root/'routing/publish_routing.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
def git(repo,*args):
    return subprocess.check_output(['git','-C',str(repo),*args],stderr=subprocess.STDOUT,text=True).strip()

with tempfile.TemporaryDirectory() as directory:
    tmp=Path(directory); remote=tmp/'remote.git'; repo=tmp/'scanner'; other=tmp/'other'
    subprocess.run(['git','init','--bare',str(remote)],check=True,capture_output=True)
    subprocess.run(['git','clone',str(remote),str(repo)],check=True,capture_output=True)
    git(repo,'config','user.name','Test');git(repo,'config','user.email','test@example.invalid')
    git(repo,'checkout','-b','test')
    for path in module.INPUTS[:-1]:
        target=repo/path;target.parent.mkdir(parents=True,exist_ok=True);target.write_text('initial\n')
    git(repo,'add','.');git(repo,'commit','-m','Initial');git(repo,'push','origin','test')
    base=git(repo,'rev-parse','HEAD')
    subprocess.run(['git','clone','--branch','test',str(remote),str(other)],check=True,capture_output=True)
    git(other,'config','user.name','Test');git(other,'config','user.email','test@example.invalid')
    (other/'unrelated.txt').write_text('keep this\n')
    git(other,'add','.');git(other,'commit','-m','Concurrent unrelated change');git(other,'push')
    latest=git(other,'rev-parse','HEAD')
    payload=tmp/'IP.json';payload.write_text('{"rules":[]}\n')
    domain_payload=tmp/'domains.json';domain_payload.write_text('{"rules":[]}\n')
    sources_payload=tmp/'sources.json';sources_payload.write_text('{"rules":[]}\n')
    module.publish(repo,payload,base,domains=domain_payload,sources=sources_payload)
    published=git(other,'ls-remote','origin','refs/heads/test').split()[0]
    git(other,'fetch','origin','test')
    assert git(other,'rev-parse',published+'^')==latest
    assert git(other,'show',published+':unrelated.txt')=='keep this'
    assert git(other,'show',published+':'+module.OUTPUT)=='{"rules":[]}'
    assert git(other,'show',published+':source/routing/domains.json')=='{"rules":[]}'
    assert set(git(other,'diff-tree','--no-commit-id','--name-only','-r',published).splitlines())=={module.OUTPUT,'source/routing/domains.json','source/routing/sources.json'}
    assert git(repo,'status','--porcelain')==''
    assert git(repo,'worktree','list','--porcelain').count('worktree ')==1
    module.publish(repo,payload,published)
    assert git(other,'ls-remote','origin','refs/heads/test').split()[0]==published
    # Advance the real remote between fetch and push; retry must keep that commit.
    git(other,'reset','--hard',published)
    payload.write_text('{"rules":[{"ruleTag":"new","ip":[]}]}\n')
    original_git=module.git
    raced=[]
    def race_git(directory,*args,**kwargs):
        if args and args[0]=='push' and not raced:
            (other/'unrelated.txt').write_text('concurrent push\n')
            git(other,'add','.');git(other,'commit','-m','Race before push');git(other,'push')
            raced.append(git(other,'rev-parse','HEAD'))
        return original_git(directory,*args,**kwargs)
    module.git=race_git
    try:module.publish(repo,payload,published)
    finally:module.git=original_git
    published=git(other,'ls-remote','origin','refs/heads/test').split()[0]
    git(other,'fetch','origin','test')
    assert git(other,'rev-parse',published+'^')==raced[0]
    assert git(other,'show',published+':unrelated.txt')=='concurrent push'
    # A changed scan input must never publish obsolete results.
    git(other,'reset','--hard',published)
    (other/module.INPUTS[0]).write_text('changed.example\n')
    git(other,'add','.');git(other,'commit','-m','Change sites');git(other,'push')
    changed=git(other,'rev-parse','HEAD')
    try:module.publish(repo,payload,published)
    except RuntimeError as error:assert 'changed during scan' in str(error)
    else:raise AssertionError('Stale scan was published')
    assert git(other,'ls-remote','origin','refs/heads/test').split()[0]==changed
    # The previous output also belongs to the input snapshot used for partial unions.
    (other/module.OUTPUT).write_text('newer output\n')
    git(other,'add','.');git(other,'commit','-m','Other update');git(other,'push')
    try:module.publish(repo,payload,changed)
    except RuntimeError as error:assert 'changed during scan' in str(error)
    else:raise AssertionError('Newer IP.json was overwritten')
    try:module.publish(repo,payload,changed,branch='main')
    except ValueError:pass
    else:raise AssertionError('main publication enabled')
print('PASS latest-parent publication, concurrent edit retained, unchanged no-op, stale sites/output rejected, worktree cleaned')
