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
    for path in module.LISTS + module.INPUTS[:-1]:
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
    # A newer input list remains untouched while collected results are published.
    git(other,'reset','--hard',published)
    (other/module.LISTS[0]).write_text('changed.example\n')
    (other/module.LISTS[1]).write_text('AS123\n')
    git(other,'add','.');git(other,'commit','-m','Change lists');git(other,'push')
    list_commit=git(other,'rev-parse','HEAD')
    payload.write_text('{"rules":[{"ruleTag":"result","ip":["192.0.2.0/24"]}]}\n')
    module.publish(repo,payload,published)
    changed=git(other,'ls-remote','origin','refs/heads/test').split()[0]
    git(other,'fetch','origin','test')
    assert git(other,'rev-parse',changed+'^')==list_commit
    assert git(other,'show',changed+':'+module.LISTS[0])=='changed.example'
    assert git(other,'show',changed+':'+module.LISTS[1])=='AS123'
    git(other,'reset','--hard',changed)
    # The previous output also belongs to the input snapshot used for partial unions.
    (other/module.OUTPUT).write_text('newer output\n')
    git(other,'add','.');git(other,'commit','-m','Other update');git(other,'push')
    try:module.publish(repo,payload,changed)
    except RuntimeError as error:assert 'changed during scan' in str(error)
    else:raise AssertionError('Newer IP.json was overwritten')
    try:
        module.publish_payloads(repo, changed, {module.REPORT: b'# Old report\n'},
                                module.REPORT_INPUTS, 'Report')
    except RuntimeError as error:
        assert module.OUTPUT in str(error)
    else:
        raise AssertionError('Report was published for a replaced IP.json')
    latest = git(other, 'rev-parse', 'HEAD')
    module.publish_payloads(repo, latest, {module.REPORT: b'# Current report\n'},
                            module.REPORT_INPUTS, 'Report')
    report_commit = git(other, 'ls-remote', 'origin', 'refs/heads/test').split()[0]
    git(other, 'fetch', 'origin', 'test')
    assert git(other, 'diff-tree', '--no-commit-id', '--name-only', '-r', report_commit) == module.REPORT
    assert git(other, 'show', f'{report_commit}:{module.REPORT}') == '# Current report'
    try:module.publish(repo,payload,changed,branch='main')
    except ValueError:pass
    else:raise AssertionError('main publication enabled')
print('PASS latest-parent publication, concurrent edit retained, unchanged no-op, newer lists retained and newer output protected, worktree cleaned')
