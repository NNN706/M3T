"""Separate domain/IP files, domain attribution and persistent one-time legacy import."""
import importlib.util
import ipaddress
import json
from pathlib import Path
import subprocess
import tempfile
root=Path(__file__).resolve().parents[1]/'routing'
spec=importlib.util.spec_from_file_location('routing',root/'update_routing.py')
routing=importlib.util.module_from_spec(spec);spec.loader.exec_module(routing)
raw={'rules':[{'ruleTag':'a.example','ip':['192.0.2.0/25'],'domain':['domain:a.example','domain:api.a.example','domain:shared.example','domain:api.a.example']},
              {'ruleTag':'b.example','ip':['198.51.100.0/24'],'domain':['domain:b.example','domain:shared.example']}]}
domains=routing.domain_rules(raw,['a.example','b.example'])
assert domains['rules'][0]['domain']==['domain:a.example','domain:api.a.example','domain:shared.example']
assert domains['rules'][1]['domain']==['domain:b.example','domain:shared.example']
with tempfile.TemporaryDirectory() as directory:
    tmp=Path(directory);sites=tmp/'sites.txt';sites.write_text('a.example\nb.example\n')
    output=tmp/'IP.json';domain_file=tmp/'domains.json';scanner=tmp/'scan.sh'
    legacy={'ruleTag':'legacy','ip':['10.0.0.0/8','2001:db8::/32']}
    output.write_text(json.dumps({'rules':[{'ruleTag':'a.example','ip':['192.0.2.128/25']},legacy]}))
    domain_file.write_text(json.dumps({'rules':[{'ruleTag':'a.example','domain':['domain:old.a.example']}]}))
    def run(code):
        scanner.write_text("printf '%s\\n' '"+json.dumps(raw)+"'\nexit "+str(code)+'\n')
        return subprocess.run(['python3',str(root/'update_routing.py'),'--allow-partial','--sites',str(sites),'--output',str(output),'--scanner',str(scanner)],capture_output=True,text=True)
    result=run(3);assert result.returncode==0,result.stderr
    ip_rules=json.loads(output.read_text())['rules'];assert ip_rules[0]['ip']==['192.0.2.0/24']
    assert legacy in ip_rules
    assert 'domain:old.a.example' in json.loads(domain_file.read_text())['rules'][0]['domain']
    assert all('domain' not in r for r in ip_rules)
    result=run(0);assert result.returncode==0,result.stderr
    assert legacy in json.loads(output.read_text())['rules']
    assert 'domain:old.a.example' not in json.loads(domain_file.read_text())['rules'][0]['domain']
    old_ip=output.read_text();old_domains=domain_file.read_text()
    raw['rules'][0]['domain']=['https://invalid.example/path']
    result=run(0);assert result.returncode!=0
    assert output.read_text()==old_ip and domain_file.read_text()==old_domains
# Validate the actual committed migration outputs too.
ips=json.loads((root/'IP.json').read_text())['rules']
assert len({r['ruleTag'] for r in ips})==len(ips)
for rule in ips:
    nets=[ipaddress.ip_network(x,strict=True) for x in rule['ip']]
    assert len(nets)==len(set(nets))
    assert nets==[n for version in (4,6) for n in ipaddress.collapse_addresses(n for n in nets if n.version==version)]
current_domains=json.loads((root/'domains.json').read_text())
entries=routing.services(root/'sites.txt')
assert current_domains==routing.domain_rules(current_domains,[host for host,_ in entries])
assert (root/'ASN.txt').exists()
assert not (root/'IP.txt').exists()
assert not (root.parent/'ip/IP.txt').exists()
assert not (root.parent/'ip/ASN.txt').exists()
print('PASS separate JSON outputs, source domain attribution, partial union, persistent IPv4/IPv6 legacy, invalid domain atomic rejection, migration data')
