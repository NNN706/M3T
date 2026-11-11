"""Cross-tag exact aggregation, source attribution, removals and partial retention."""
import importlib.util,json,pathlib,subprocess,tempfile,random,ipaddress
root=pathlib.Path(__file__).resolve().parents[1]/'routing'
spec=importlib.util.spec_from_file_location('routing',root/'scripts/update_routing.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
original={'rules':[{'ruleTag':'b.example','ip':['192.0.2.128/25','2001:db8::/33']},{'ruleTag':'a.example','ip':['192.0.2.0/25','192.0.2.0/25','2001:db8:8000::/33']}]}
expected={'rules':[{'ruleTag':'a.example','ip':['192.0.2.0/24','2001:db8::/32']}]}
assert m.global_rules(original)==expected
original['rules'].reverse();assert m.global_rules(original)==expected
# Independently enumerate small randomized address sets to check coverage and uniqueness.
rng=random.Random(13)
for _ in range(40):
    data={'rules':[{'ruleTag':tag,'ip':[str(ipaddress.ip_network((int(ipaddress.ip_address('198.51.100.0'))+offset,32))) for offset in range(32) if rng.randrange(3)==0]} for tag in ('c','b','a')]}
    result=m.global_rules(data)
    before={int(ipaddress.ip_address(x.split('/')[0])) for r in data['rules'] for x in r['ip']}
    after=[int(ip) for r in result['rules'] for x in r['ip'] for ip in ipaddress.ip_network(x)]
    assert before==set(after) and len(after)==len(set(after))
with tempfile.TemporaryDirectory() as directory:
    tmp=pathlib.Path(directory);sites=tmp/'sites.txt';sites.write_text('a.example b.example\n');scanner=tmp/'scan.sh';output=tmp/'IP.json'
    command=['python3',str(root/'scripts/update_routing.py'),'--allow-partial','--sites',str(sites),'--scanner',str(scanner),'--output',str(output)]
    def run(data,code):
        scanner.write_text("printf '%s\\n' '"+json.dumps(data)+"'\nexit "+str(code)+'\n')
        result=subprocess.run(command,capture_output=True,text=True);assert result.returncode==0,result.stderr
        return json.loads(output.read_text())
    first={'rules':[{'ruleTag':'a.example','ip':['192.0.2.0/25']},{'ruleTag':'b.example','ip':['192.0.2.128/25']}]}
    assert run(first,0)['rules']==[{'ruleTag':'a.example','ip':['192.0.2.0/24']}]
    assert len(json.loads((tmp/'sources.json').read_text())['rules'])==2
    second={'rules':[{'ruleTag':'a.example','ip':['198.51.100.0/24']},{'ruleTag':'b.example','ip':[]}]}
    assert run(second,3)['rules']==[{'ruleTag':'a.example','ip':['192.0.2.0/24','198.51.100.0/24']}]
    assert run(second,0)['rules']==[{'ruleTag':'a.example','ip':['198.51.100.0/24']}]
    run(first,0)
    sites.write_text('a.example\n')
    assert run({'rules':[first['rules'][0]]},3)['rules']==[{'ruleTag':'a.example','ip':['192.0.2.0/25']}]
# Only whole legacy blocks move; global aggregation still prefers a named storage group.
legacy_data = {'rules': [
    {'ruleTag': 'legacy', 'ip': ['192.0.2.0/24', '2001:db8::/32']},
    {'ruleTag': 'z.example', 'ip': ['192.0.2.0/25', '2001:db8::/33']},
]}
separated = m.redistribute_legacy(legacy_data)
assert separated == legacy_data
assert m.global_rules(legacy_data) == {'rules': [
    {'ruleTag': 'z.example', 'ip': ['192.0.2.0/24', '2001:db8::/32']},
]}
assert m.redistribute_legacy(separated) == separated
assert m.global_rules({'rules': [legacy_data['rules'][0],
    {'ruleTag': 'z.example', 'ip': legacy_data['rules'][0]['ip']}]}) == {
        'rules': [{'ruleTag': 'z.example', 'ip': legacy_data['rules'][0]['ip']}]}

# Compare the generated IP data independently of deployment policy.
published = json.loads((root/'generated/IP.json').read_text())
published['rules'] = [
    {key: value for key, value in rule.items() if key != 'outboundTag'}
    for rule in published['rules']
]
assert published == m.global_rules(json.loads((root/'state/sources.json').read_text())), (
    'IP.json differs from the global projection of sources.json (ignoring outboundTag)'
)
print('PASS cross-tag IPv4/IPv6 collapse, deterministic assignment, randomized exact coverage, partial retention, full-scan deletion, removed-service cleanup')
