"""Scan services and atomically write deduplicated Xray rule fragments (Python stdlib)."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import tempfile
import sys
from urllib.parse import urlsplit


def services(path):
    result = []
    seen = set()
    for line in path.read_text().splitlines():
        line = line.split('#', 1)[0].strip()
        if not line:
            continue
        for value in line.split():
            url = urlsplit(value if '://' in value else 'https://' + value)
            if url.scheme not in ('http', 'https') or not url.hostname or url.username or url.password:
                raise ValueError('Expected a domain or HTTP(S) URL without credentials')
            host = url.hostname.lower().rstrip('.')
            if host not in seen:
                seen.add(host)
                result.append((host, value))
    if not result:
        raise ValueError('sites.txt is empty: add one service domain or URL per line')
    return result


def compact_rules(data, expected):
    rules = data['rules']
    if not isinstance(rules, list) or [r['ruleTag'] for r in rules] != sorted(expected):
        raise ValueError('Unexpected service tags in scanner result')
    result = []
    for rule in rules:
        if not isinstance(rule['ip'], list):
            raise ValueError('No prefixes for service ' + rule['ruleTag'])
        networks = [ipaddress.IPv4Network(value, strict=True) for value in rule['ip']]
        result.append({'ruleTag': rule['ruleTag'], 'ip': [str(n) for n in ipaddress.collapse_addresses(networks)]})
    return {'rules': result}


def global_rules(data):
    """Exact union across tags; assign each CIDR once to the first contributing tag."""
    tagged = []
    for rule in data['rules']:
        if set(rule) != {'ruleTag', 'ip'}:
            raise ValueError('Global IP grouping accepts only ruleTag/ip fragments')
        for value in rule['ip']:
            tagged.append((rule['ruleTag'], ipaddress.ip_network(value, strict=True)))
    collapsed = [n for version in (4,6) for n in ipaddress.collapse_addresses(n for _,n in tagged if n.version==version)]
    groups = {}
    for network in collapsed:
        tag = min(tag for tag,original in tagged if original.version==network.version and original.overlaps(network))
        groups.setdefault(tag, []).append(str(network))
    result = {'rules':[{'ruleTag':tag, 'ip':groups[tag]} for tag in sorted(groups)]}
    # Independent integer interval check, not another call to collapse_addresses.
    def coverage(networks):
        merged = []
        for version,lo,hi in sorted((n.version,int(n.network_address),int(n.broadcast_address)) for n in networks):
            if merged and merged[-1][0]==version and lo<=merged[-1][2]+1:
                merged[-1]=(version,merged[-1][1],max(hi,merged[-1][2]))
            else:
                merged.append((version,lo,hi))
        return merged
    output = [ipaddress.ip_network(value) for rule in result['rules'] for value in rule['ip']]
    if coverage(n for _,n in tagged) != coverage(output):
        raise ValueError('Global grouping changed address coverage')
    ordered = sorted(output, key=lambda n:(n.version,int(n.network_address)))
    if any(a.version==b.version and int(a.broadcast_address)>=int(b.network_address) for a,b in zip(ordered,ordered[1:])):
        raise ValueError('Duplicate or overlapping output prefixes')
    return result


def domain_rules(data, expected):
    import re
    rules = data['rules']
    if [r['ruleTag'] for r in rules] != sorted(expected):
        raise ValueError('Unexpected domain service tags')
    result = []
    for rule in rules:
        values = rule.get('domain', ['domain:' + rule['ruleTag']])
        if not isinstance(values, list):
            raise ValueError('Expected domain array')
        hosts = {rule['ruleTag']}
        for value in values:
            if not isinstance(value, str) or not value.startswith('domain:'):
                raise ValueError('Invalid domain matcher')
            host = value[len('domain:'):].lower().rstrip('.')
            if len(host)>253 or len(host.split('.'))<2 or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in host.split('.')):
                raise ValueError('Invalid domain matcher')
            hosts.add(host)
        result.append({'ruleTag':rule['ruleTag'], 'domain':['domain:'+host for host in sorted(hosts)]})
    return {'rules':result}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    root = Path(__file__).resolve().parent
    parser.add_argument('--sites', type=Path, default=root / 'sites.txt')
    parser.add_argument('--output', type=Path, default=root / 'IP.json')
    parser.add_argument('--sources-output', type=Path, help='Original per-service prefixes before global grouping')
    parser.add_argument('--domains-output', type=Path, help='Defaults to domains.json beside IP.json')
    parser.add_argument('--allow-partial', action='store_true', help='Keep available prefixes and union previous entries on incomplete scans')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show detailed scanner stages on stderr')
    parser.add_argument('--evidence', type=Path, help='Directory for raw scan output and completeness report')
    parser.add_argument('--scanner', type=Path, default=root.parent / 'SubnetResolve.sh')
    args = parser.parse_args()
    entries = services(args.sites)
    if args.sources_output is None:
        args.sources_output = args.output.with_name('sources.json')
    if args.domains_output is None:
        args.domains_output = args.output.with_name('domains.json')
    scan = subprocess.run(['bash', str(args.scanner), '-parse', '-rules', '-s', *(['-v'] if args.verbose else []), '--', *[value for _, value in entries]],
                          stdout=subprocess.PIPE, text=True, timeout=6600)
    if args.evidence:
        args.evidence.mkdir(parents=True, exist_ok=True)
        (args.evidence / 'scanner-output.json').write_text(scan.stdout)
    if scan.returncode != 0 and not (args.allow_partial and scan.returncode == 3):
        raise RuntimeError('Scan incomplete or failed; existing IP.json/domains.json retained. See stderr above.')
    data = json.loads(scan.stdout)
    result = compact_rules(data, [host for host, _ in entries])
    domains = domain_rules(data, [host for host, _ in entries])
    missing = [r['ruleTag'] for r in result['rules'] if not r['ip']]
    previous_path = args.sources_output if args.sources_output.exists() else args.output
    if scan.returncode == 3 and previous_path.exists():
        previous = json.loads(previous_path.read_text())
        old = {r['ruleTag']: r['ip'] for r in previous['rules']}
        for rule in result['rules']:
            rule['ip'] += old.get(rule['ruleTag'], [])
        result = compact_rules(result, [host for host, _ in entries])
    result['rules'] = [r for r in result['rules'] if r['ip']]
    if not result['rules']:
        raise RuntimeError('No usable prefixes; existing IP.json/domains.json retained.')
    if previous_path.exists():
        old_rules = json.loads(previous_path.read_text())['rules']
        for rule in old_rules:
            if rule['ruleTag'] == 'legacy':
                networks = [ipaddress.ip_network(value, strict=True) for value in rule['ip']]
                result['rules'].append({'ruleTag':'legacy', 'ip':[str(n) for version in (4,6) for n in ipaddress.collapse_addresses(n for n in networks if n.version==version)]})
    if scan.returncode == 3 and args.domains_output.exists():
        previous_domains = json.loads(args.domains_output.read_text())
        old = {r['ruleTag']:r['domain'] for r in previous_domains['rules']}
        for rule in domains['rules']:
            rule['domain'] = sorted(set(rule['domain'] + old.get(rule['ruleTag'], [])))
        domains = domain_rules(domains, [host for host, _ in entries])
    sources = {'rules':sorted(result['rules'], key=lambda r:r['ruleTag'])}
    result = global_rules(sources)
    if args.evidence:
        (args.evidence / 'completeness.json').write_text(json.dumps({
            'complete': scan.returncode == 0, 'services_without_new_prefixes': missing,
            'services_written': len(result['rules']),
            'prefixes_written': sum(len(r['ip']) for r in result['rules'])}, indent=2) + '\n')
    if scan.returncode == 3:
        print('WARNING: неполный сбор; сохранены доступные и прежние подсети. Подробности в артефактах запуска.', file=sys.stderr)

    write_json(args.output, result)
    write_json(args.domains_output, domains)
    write_json(args.sources_output, sources)


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', dir=path.parent, delete=False) as stream:
            temporary = stream.name
            json.dump(data, stream, ensure_ascii=False, indent=2)
            stream.write('\n')
        os.replace(temporary, path)
    finally:
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)


if __name__ == '__main__':
    main()
