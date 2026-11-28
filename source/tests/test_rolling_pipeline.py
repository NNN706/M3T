"""Every browser work unit reaches DNS; deadline publication and journal resume."""
import argparse,contextlib,io,json,subprocess,sys,tempfile
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'routing/scripts'))
from update_routing import incremental_update,write_json
scanner=Path(__file__).resolve().parents[1]/'SubnetResolve.sh'
with tempfile.TemporaryDirectory() as directory:
    tmp=Path(directory)
    args=argparse.Namespace(scanner=scanner,verbose=False,allow_partial=True,full_refresh=True,
        domains_output=tmp/'domains.json',sources_output=tmp/'sources.json',output=tmp/'IP.json',evidence=tmp/'one',resume=None)
    write_json(args.sources_output,{'rules':[{'ruleTag':'legacy','ip':['198.51.100.0/24']}]})
    entries=[(f'h{i:03}.example',f'https://h{i:03}.example/Path?Case=YES') for i in range(260)]
    events=[];clock=[0];dns_count=[0]
    def run(command,**kwargs):
        if command[1]=='-c':
            urls=kwargs['input'].split();events.append(('browser',urls))
            pages=[{'site':url.split('/')[2],'domains':[],'errors':[]} for url in urls]
            clock[0]+=100
            return subprocess.CompletedProcess(command,0,json.dumps({'pages':pages}))
        hosts=command[command.index('--')+1:];events.append(('dns',hosts));dns_count[0]+=1
        rows=[]
        for host in hosts:
            if host=='h001.example':
                rows.append({'domain':host,'complete':False,'results':[],
                             'errors':[{'check_host':'n','error':'No A records'}]})
            else:
                rows.append({'domain':host,'complete':True,'results':[{'prefix':'11.0.0.0/24','asn':'AS1'}],'errors':[]})
        if dns_count[0]==3:clock[0]=13201
        return subprocess.CompletedProcess(command,0,json.dumps({'domains':rows}))
    with patch('update_routing.time.monotonic',side_effect=lambda:clock[0]),patch('update_routing.subprocess.run',side_effect=run),contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
        incremental_update(args,entries,set(),lambda *_:([],[],''))
    assert [phase for phase,_ in events]==['browser','dns','dns','dns']
    assert len(events[0][1])==128
    status=json.loads((args.evidence/'completeness.json').read_text())
    assert status['sites_total']==260 and status['sites_browser_pending']==132 and not status['complete']
    assert json.loads(args.output.read_text())['rules'] and (args.evidence/'prepared.json').exists()
    published_names={m[7:] for r in json.loads(args.domains_output.read_text())['rules'] for m in r['domain']}
    assert 'h000.example' in published_names and 'h128.example' not in published_names
    journal=args.evidence/'dns-checkpoint.ndjson'
    rows=[json.loads(line) for line in journal.read_text().splitlines()]
    assert len(rows)==90 and any(r['domain']=='h001.example' and not r['results'] for r in rows)
    print('PASS browser→DNS order, deadline reserve publishes partial results and leaves unvisited seeds pending')

    # Simulate a hard stop before the final JSON snapshot, followed by normal
    # publication: exact prepared outputs become the current baseline.
    (args.evidence/'dns-checkpoint.json').write_text('{}')
    with journal.open('a') as stream:stream.write('{"interrupted":')
    args.resume=args.evidence;args.evidence=tmp/'two';events.clear();clock[0]=0;dns_count[0]=100
    with patch('update_routing.time.monotonic',side_effect=lambda:clock[0]),patch('update_routing.subprocess.run',side_effect=run),contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
        incremental_update(args,entries,set(),lambda *_:([],[],''))
    assert events[0][0]=='dns' and events[0][1][0]=='h090.example'
    queried=[host for phase,hosts in events if phase=='dns' for host in hosts]
    assert all(f'h{i:03}.example' not in queried for i in range(90))
    browsed=[url.split('/')[2] for phase,urls in events if phase=='browser' for url in urls]
    assert len(browsed)==132 and browsed[0]=='h128.example'
    assert json.loads((args.evidence/'completeness.json').read_text())['domains_without_complete_dns_bgp']==['h001.example']
    assert json.loads((args.evidence/'completeness.json').read_text())['sites_browser_pending']==0
    print('PASS resume after partial publication drains saved DNS first, skips terminal no-A and restores journal despite truncated tail')
