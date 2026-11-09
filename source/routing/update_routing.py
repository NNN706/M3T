"""Scan services and atomically write deduplicated Xray rule fragments (Python stdlib)."""
import argparse
from collections import Counter
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import tempfile
import sys
from urllib.parse import urlsplit


def services(path, parse_asn=None):
    result = []
    seen = set()
    for line in path.read_text().splitlines():
        line = line.split('#', 1)[0].strip()
        if not line:
            continue
        for value in line.split():
            origin = parse_asn(value) if parse_asn else None
            if origin:
                if origin not in seen:
                    seen.add(origin)
                    result.append((origin, value))
                continue
            url = urlsplit(value if '://' in value else 'https://' + value)
            if url.scheme not in ('http', 'https') or not url.hostname or url.username or url.password:
                raise ValueError('Expected a domain or HTTP(S) URL without credentials')
            host = url.hostname.lower().rstrip('.')
            key = value if host == 'bgp.he.net' else host
            if key not in seen:
                seen.add(key)
                result.append((host, value))
    return result


def validate_rule_tags(data, expected, context):
    rules = data.get('rules') if isinstance(data, dict) else None
    if not isinstance(rules, list):
        raise ValueError(f'{context}: поле rules должно быть массивом')
    tags = []
    for index, rule in enumerate(rules):
        tag = rule.get('ruleTag') if isinstance(rule, dict) else None
        if not isinstance(tag, str) or not tag.strip():
            raise ValueError(f'{context}: rules[{index}].ruleTag должен быть непустой строкой, получено {tag!r}')
        tags.append(tag)

    counts = Counter(tags)
    required = set(expected)
    issues = []
    for label, values in (
        ('нет тегов', sorted(required - counts.keys())),
        ('лишние теги', sorted(counts.keys() - required)),
        ('повторяющиеся теги', sorted(tag for tag, count in counts.items() if count > 1)),
    ):
        if values:
            issues.append(f'{label}: {", ".join(map(repr, values))}')
    if issues:
        raise ValueError(f'{context}: ' + '; '.join(issues))
    if tags != sorted(tags):
        raise ValueError(f'{context}: ruleTag должны идти по алфавиту, получено {tags!r}')
    return rules


def compact_rules(data, expected, dual_stack=False):
    rules = validate_rule_tags(data, expected, 'Правила IP')
    result = []
    for rule in rules:
        if not isinstance(rule['ip'], list):
            raise ValueError('No prefixes for service ' + rule['ruleTag'])
        networks = [(ipaddress.ip_network if dual_stack else ipaddress.IPv4Network)(value, strict=True) for value in rule['ip']]
        result.append({'ruleTag': rule['ruleTag'], 'ip': [str(n) for version in (4, 6) for n in ipaddress.collapse_addresses(n for n in networks if n.version == version)]})
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


def domain_rules(data, expected, *, include_seed=True):
    import re
    rules = validate_rule_tags(data, expected, 'Правила доменов')
    result = []
    for rule in rules:
        values = rule.get('domain', ['domain:' + rule['ruleTag']] if include_seed else None)
        if not isinstance(values, list):
            raise ValueError('Expected domain array')
        hosts = {rule['ruleTag']} if include_seed else set()
        for value in values:
            if not isinstance(value, str) or not value.startswith('domain:'):
                raise ValueError('Invalid domain matcher')
            host = value[len('domain:'):].lower().rstrip('.')
            if len(host)>253 or len(host.split('.'))<2 or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in host.split('.')):
                raise ValueError('Invalid domain matcher')
            hosts.add(host)
        result.append({'ruleTag':rule['ruleTag'], 'domain':['domain:'+host for host in sorted(hosts)]})
    return {'rules':result}


def incremental_update(args, entries, explicit, collect):
    """Workflow mode. Append verified discoveries to the published baseline."""
    previous_domains = json.loads(args.domains_output.read_text()) if args.domains_output.exists() else {'rules': []}
    if args.output.exists() and not args.sources_output.exists():
        raise RuntimeError('Инкрементальный сбор требует sources.json для сохранения групп подсетей.')
    previous_sources = json.loads(args.sources_output.read_text()) if args.sources_output.exists() else {'rules': []}
    previous_tags = [r['ruleTag'] for r in previous_domains['rules']]
    previous_domains = domain_rules(previous_domains, previous_tags, include_seed=False)
    domain_groups = {r['ruleTag']: set(r['domain']) for r in previous_domains['rules']}
    source_groups = {r['ruleTag']: set(r['ip']) for r in previous_sources['rules']}
    known = {matcher.lower().rstrip('.') for group in domain_groups.values()
             for matcher in group if matcher.startswith('domain:')}
    discovery = {'domains': [], 'pages': [], 'complete': True}
    flags = ['-v'] if args.verbose else []
    if entries:
        # Reuse the production curl/Chromium phase without executing its DNS phase.
        # Fail closed if SubnetResolve changes its phase boundary.
        marker = "\nunset inputs\nstage_name='Этап 3/4: DNS'\n"
        scanner = args.scanner.read_text()
        if scanner.count(marker) != 1:
            raise RuntimeError('Не найдена граница этапов Chromium и DNS в SubnetResolve.sh.')
        browser_phase = scanner.split(marker, 1)[0] + '\nfinish_progress\ncat "$batch/discovery.json"\n'
        browser = subprocess.run(['bash', '-c', browser_phase, str(args.scanner), '-parse', '-s',
                                  *flags, '--', *[url for _, url in entries]],
                                 stdout=subprocess.PIPE, text=True, timeout=6600, check=True)
        discovery = json.loads(browser.stdout)
    tags = {host for host, _ in entries}
    candidates = {host: {host} for host in tags}
    for page in discovery['pages']:
        candidates[page['site']].update(page['domains'])
        for error in page['errors']:
            message = error.removesuffix('; домен будет проверен через DNS/BGP')
            print(f"[{page['site']}] {message}", file=sys.stderr)
    discovered = set().union(*candidates.values())
    pending = sorted(host for host in discovered if 'domain:' + host not in known)
    print(f'DNS Check-Host: новых доменов {len(pending)}, уже в domains.json {len(discovered)-len(pending)}.', flush=True)
    observations = []
    responses = {}
    if args.evidence:
        args.evidence.mkdir(parents=True, exist_ok=True)
        write_json(args.evidence / 'discovery.json', discovery)
    if pending:
        scan = subprocess.run(['bash', str(args.scanner), '-s', *flags, '--', *pending],
                              stdout=subprocess.PIPE, text=True, timeout=6600)
        if args.evidence:
            (args.evidence / 'scanner-output.json').write_text(scan.stdout)
        if scan.returncode not in (0, 3):
            raise RuntimeError(f'DNS/BGP-сканирование завершилось с ошибкой {scan.returncode}. См. журнал.')
        data = json.loads(scan.stdout)
        rows = data['domains'] if 'domains' in data else [data]
        responses = {row['domain']: row for row in rows}
        if len(responses) != len(rows) or set(responses) != set(pending):
            raise ValueError(f'DNS/BGP вернул другой список доменов. Нет: {sorted(set(pending)-responses.keys())}. '
                             f'Лишние: {sorted(responses.keys()-set(pending))}.')
    resolved = {}
    for host, row in responses.items():
        if row['complete'] and row['results']:
            resolved[host] = {str(ipaddress.ip_network(route['prefix'])) for route in row['results']}
            observations.extend(row['results'])
    unresolved = sorted(set(pending) - resolved.keys())
    if unresolved:
        print('DNS/BGP без полного результата. Домены остаются на повтор: ' + ', '.join(unresolved), file=sys.stderr)
    if args.evidence:
        write_json(args.evidence / 'bgp-observations.json', observations)
    as_rules, as_missing, report = collect(explicit, observations)
    print(report, flush=True)
    for rule in as_rules:
        if rule['ip']:
            source_groups.setdefault(rule['ruleTag'], set()).update(rule['ip'])
    for tag, hosts in candidates.items():
        for host in sorted(hosts & resolved.keys()):
            domain_groups.setdefault(tag, set()).add('domain:' + host)
            source_groups.setdefault(tag, set()).update(resolved[host])
    sources = {'rules': [{'ruleTag': tag, 'ip': sorted(values)} for tag, values in sorted(source_groups.items())]}
    sources = compact_rules(sources, source_groups, dual_stack=True)
    domains = {'rules': [{'ruleTag': tag, 'domain': sorted(values)} for tag, values in sorted(domain_groups.items())]}
    domains = domain_rules(domains, domain_groups, include_seed=False)
    result = global_rules(sources)
    complete = discovery['complete'] and not unresolved and not as_missing
    if args.evidence:
        (args.evidence / 'asn-report.md').write_text(report)
        write_json(args.evidence / 'completeness.json', {
            'complete': complete, 'mode': 'incremental', 'dns_requested': len(pending),
            'dns_skipped_existing': len(discovered) - len(pending),
            'domains_without_complete_dns_bgp': unresolved, 'asns_without_prefixes': as_missing,
            'services_written': len(result['rules']),
            'prefixes_written': sum(len(rule['ip']) for rule in result['rules']),
        })
    if not complete and not args.allow_partial:
        raise RuntimeError('Инкрементальный сбор неполный. Подробности в журнале.')
    write_json(args.output, result)
    write_json(args.domains_output, domains)
    write_json(args.sources_output, sources)


def main():
    from asn_routes import asn, collect
    parser = argparse.ArgumentParser(description=__doc__)
    root = Path(__file__).resolve().parent
    parser.add_argument('--sites', type=Path, default=root / 'sites.txt')
    parser.add_argument('--asn-file', type=Path)
    parser.add_argument('--output', type=Path, default=root / 'IP.json')
    parser.add_argument('--sources-output', type=Path, help='Original per-service prefixes before global grouping')
    parser.add_argument('--domains-output', type=Path, help='Defaults to domains.json beside IP.json')
    parser.add_argument('--incremental', action='store_true', help='Resolve only names absent from published domain rules')
    parser.add_argument('--allow-partial', action='store_true', help='Keep available prefixes and union previous entries on incomplete scans')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show detailed scanner stages on stderr')
    parser.add_argument('--evidence', type=Path, help='Directory for raw scan output and completeness report')
    parser.add_argument('--scanner', type=Path, default=root.parent / 'SubnetResolve.sh')
    args = parser.parse_args()
    entries = services(args.sites, asn)
    explicit = {tag for tag, _ in entries if asn(tag)}
    entries = [(tag, value) for tag, value in entries if not asn(tag)]
    asn_file = args.asn_file or args.sites.with_name('ASN.txt')
    if asn_file.exists() or args.asn_file:
        for tag, value in services(asn_file, asn):
            origin = asn(tag)
            if not origin and tag == 'bgp.he.net':
                origin = asn(urlsplit(value).path.strip('/'))
            if not origin:
                raise ValueError(f'Invalid ASN entry: {value}')
            explicit.add(origin)
    if not entries and not explicit:
        raise ValueError('No domains or ASNs configured')
    if args.sources_output is None:
        args.sources_output = args.output.with_name('sources.json')
    if args.domains_output is None:
        args.domains_output = args.output.with_name('domains.json')
    if args.incremental:
        incremental_update(args, entries, explicit, collect)
        return
    with tempfile.TemporaryDirectory(prefix='routing-bgp-') as directory:
        metadata = Path(directory) / 'observations.json'
        scan = subprocess.run(
            ['bash', str(args.scanner), '-parse', '-rules', '-s',
             *(['-v'] if args.verbose else []), '--', *[value for _, value in entries]],
            stdout=subprocess.PIPE, text=True, timeout=6600,
            env={**os.environ, 'SUBNET_BGP_OBSERVATIONS': str(metadata)}
        ) if entries else subprocess.CompletedProcess([], 0, '{"rules":[]}')
        observations = json.loads(metadata.read_text()) if metadata.exists() else []
    if args.evidence:
        args.evidence.mkdir(parents=True, exist_ok=True)
        (args.evidence / 'scanner-output.json').write_text(scan.stdout)
        write_json(args.evidence / 'bgp-observations.json', observations)
    if scan.returncode not in (0, 3):
        raise RuntimeError('Domain scan failed; existing routing files retained.')
    data = json.loads(scan.stdout)
    domain_tags = [host for host, _ in entries]
    domains = domain_rules(data, domain_tags)
    as_rules, as_missing, report = collect(explicit, observations)
    print(report, flush=True)
    if args.evidence:
        (args.evidence / 'asn-report.md').write_text(report)
    partial = scan.returncode == 3 or bool(as_missing)
    if partial and not args.allow_partial:
        raise RuntimeError('Scan incomplete or failed; existing routing files retained.')
    expected = domain_tags + sorted(explicit)
    data['rules'] = sorted(data['rules'] + as_rules, key=lambda r: r['ruleTag'])
    result = compact_rules(data, expected, dual_stack=True)
    missing = [r['ruleTag'] for r in result['rules'] if not r['ip']]
    previous_path = args.sources_output if args.sources_output.exists() else args.output
    if partial and previous_path.exists():
        previous = json.loads(previous_path.read_text())
        old = {r['ruleTag']: r['ip'] for r in previous['rules']}
        for rule in result['rules']:
            rule['ip'] += old.get(rule['ruleTag'], [])
        result = compact_rules(result, expected, dual_stack=True)
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
            'complete': not partial, 'services_without_new_prefixes': missing,
            'services_written': len(result['rules']),
            'prefixes_written': sum(len(r['ip']) for r in result['rules'])}, indent=2) + '\n')
    if partial:
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
