"""Summarize ASN coverage of the complete published IP.json."""
import argparse
from bisect import bisect_left
from collections import Counter, defaultdict
from hashlib import sha256
import ipaddress
import json
import re
from pathlib import Path
import subprocess
import sys

from asn_routes import asn_names, cached_export, table_prefixes


def summarize(prefixes, snapshot):
    coverage = {}
    for version in (4, 6):
        ranges = list(ipaddress.collapse_addresses(n for n in prefixes if n.version == version))
        coverage[version] = (
            [int(n.network_address) for n in ranges],
            [int(n.broadcast_address) for n in ranges],
        )
    rows = {}
    for origin, announced in snapshot.items():
        touched = []
        for prefix in announced:
            network = ipaddress.ip_network(prefix)
            starts, ends = coverage[network.version]
            first, last = int(network.network_address), int(network.broadcast_address)
            index = bisect_left(ends, first)
            if index < len(starts) and starts[index] <= last:
                touched.append(network)
        if touched:
            rows['AS' + str(origin)] = (touched, len(announced))
    return rows


def read_provenance(ip_path, previous, evidence_dirs):
    published = ip_path.read_bytes()
    rules = json.loads(published)['rules']
    full_evidence = []
    for directory in evidence_dirs:
        status = directory / 'completeness.json'
        snapshot = directory / 'IP.json'
        if status.is_file() and snapshot.is_file() and snapshot.read_bytes() == published:
            metadata = json.loads(status.read_bytes())
            if metadata.get('mode') == 'full-refresh' and metadata.get('complete') is True:
                full_evidence.append(directory)
    if full_evidence:
        # Replace previous observations only for a complete scan whose routes were published.
        previous = None
        evidence_dirs = full_evidence
    networks = [ipaddress.ip_network(prefix) for rule in rules for prefix in rule['ip']]
    records = defaultdict(lambda: defaultdict(set))
    if previous is not None and previous.is_file():
        for domain, origins in json.loads(previous.read_bytes()).items():
            for origin, addresses in origins.items():
                records[domain][origin].update(addresses)

    for directory in evidence_dirs:
        paths = sorted(directory.glob('scanner-output-*.json'))
        checkpoint = directory / 'dns-checkpoint.json'
        if checkpoint.is_file():
            paths.append(checkpoint)
        for path in paths:
            try:
                data = json.loads(path.read_bytes())
            except json.JSONDecodeError:
                # Failed scanner batches can leave an empty or truncated file.
                continue
            if not isinstance(data, dict):
                continue
            if path == checkpoint:
                rows = data.values()
            else:
                rows = data.get('domains', [data])
            for row in rows:
                domain = row.get('domain', '')
                if not re.fullmatch(r'[a-z0-9-]+(?:\.[a-z0-9-]+)+', domain):
                    continue
                for route in row.get('results', []):
                    prefix = ipaddress.ip_network(route['prefix'])
                    for address in route.get('ips', []):
                        if ipaddress.ip_address(address) in prefix:
                            records[domain][route['asn']].add(address)

    result = {}
    for domain, origins in sorted(records.items()):
        active = {}
        for origin, addresses in sorted(origins.items()):
            kept = [address for address in sorted(addresses)
                    if any(ipaddress.ip_address(address) in network for network in networks)]
            if kept:
                active[origin] = kept
        if active:
            result[domain] = active
    return result


def write_verbose(output, report, rows, names, prefixes, provenance, explicit_prefixes):
    evidence = defaultdict(list)
    for domain, origins in provenance.items():
        for origin, addresses in origins.items():
            evidence[origin].extend((domain, ipaddress.ip_address(address)) for address in addresses)
    ordered = sorted(prefixes, key=lambda network: (network.version, network))
    families = {v: [network for network in ordered if network.version == v] for v in (4, 6)}
    text = ['# Подробный отчёт ASN', *report[1:],
            '',
            'Домены указаны по сохранённым ответам DNS и BGP. '
            'IP должен входить и в анонс этого ASN, и в опубликованную подсеть. '
            '«Нет наблюдений» означает, что в сохранённых данных такой связи нет.',
            '']
    matched = set()
    for origin in sorted(rows, key=lambda asn: int(asn[2:])):
        touched, _ = rows[origin]
        name = ' '.join(names.get(origin, '—').split()).replace('<', '&lt;')
        text.extend([f'## {origin} — {name}', '',
                     '| Анонс ASN | Подсети в IP.json | Домен (полученный IP) |',
                     '| --- | --- | --- |'])
        for network in sorted(touched, key=lambda n: (n.version, n)):
            published = [prefix for prefix in families[network.version] if prefix.overlaps(network)]
            matched.update(published)
            hosts = sorted({f'`{domain}` (`{address}`)' for domain, address in evidence[origin]
                            if address in network and any(address in prefix for prefix in published)})
            if not hosts:
                explicit = sorted({tag for tag, original in explicit_prefixes
                                   if original.version == network.version and original.overlaps(network)
                                   and any(prefix.overlaps(original) for prefix in published)})
                hosts = ['Ручной импорт' if tag == 'legacy' else f'Входной ASN `{tag}`' for tag in explicit]
            published_text = ', '.join(f'`{prefix}`' for prefix in published)
            text.append(f'| `{network}` | {published_text} | {", ".join(hosts) or "Нет наблюдений"} |')
        text.append('')
    unmatched = [prefix for prefix in ordered if prefix not in matched]
    if unmatched:
        text.extend(['## Подсети без совпадений в снимке BGP.tools', ''])
        text.extend(f'- `{prefix}`' for prefix in unmatched)
    output.write_text('\n'.join(text) + '\n', encoding='utf-8')


def build_report(path, *, verbose_output=None, provenance=None, sources=None):
    data = path.read_bytes()
    rules = json.loads(data)['rules']
    prefixes = {ipaddress.ip_network(prefix) for rule in rules for prefix in rule['ip']}
    counts = Counter(network.version for network in prefixes)
    rows = {}
    if prefixes:
        # A range tests membership in constant space across all 32-bit ASN values.
        all_asns = range(1, 2**32)
        snapshot = cached_export('table.jsonl', 7200, lambda path: table_prefixes(path, all_asns))
        rows = summarize(prefixes, snapshot)
    names = {}
    if rows:
        try:
            names = cached_export('asns.csv', 86400, lambda path: asn_names(path, rows))
        except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
            print(f'BGP.tools: названия ASN недоступны: {error}', file=sys.stderr)
    report = [
        '# Общее покрытие ASN правилами маршрутизации',
        '',
        f'Опубликовано **{len(prefixes)}** уникальных подсетей '
        f'(IPv4: **{counts[4]}**, IPv6: **{counts[6]}**). '
        f'С ними пересекаются анонсы **{len(rows)}** ASN.',
        '',
        'Источник правил — [IP.json](https://github.com/NNN706/M3T/blob/test/source/routing/IP.json). '
        'Анонсы сверены со снимком [BGP.tools](https://bgp.tools/kb/api).',
        '',
        f'SHA-256 файла IP.json: `{sha256(data).hexdigest()}`.',
        '',
        '«Затронуто» — анонсы ASN, которые хотя бы частично пересекаются с правилами. '
        '«Всего» — все анонсы этого ASN в снимке. '
        'Один префикс может учитываться у нескольких ASN, если они его анонсируют.',
        '',
        '| ASN | Название | Затронуто / всего |',
        '| --- | --- | ---: |',
    ]
    for origin in sorted(rows, key=lambda asn: int(asn[2:])):
        touched, total = rows[origin]
        name = ' '.join(names.get(origin, '—').split()).replace('|', '&#124;').replace('<', '&lt;')
        report.append(f'| {origin} | {name} | {len(touched)} / {total} |')
    if verbose_output is not None:
        explicit_prefixes = []
        if sources is not None:
            for rule in json.loads(sources.read_bytes())['rules']:
                tag = rule['ruleTag']
                if tag == 'legacy' or re.fullmatch(r'AS[0-9]+', tag):
                    explicit_prefixes.extend((tag, ipaddress.ip_network(prefix)) for prefix in rule['ip'])
        write_verbose(verbose_output, report, rows, names, prefixes, provenance or {}, explicit_prefixes)
    return '\n'.join(report) + '\n'


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ip_json', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--sources', type=Path)
    parser.add_argument('--verbose-output', type=Path)
    parser.add_argument('--previous-provenance', type=Path)
    parser.add_argument('--provenance-output', type=Path)
    parser.add_argument('--evidence', action='append', default=[], type=Path)
    args = parser.parse_args()
    if bool(args.verbose_output) != bool(args.provenance_output):
        parser.error('--verbose-output and --provenance-output must be used together')
    try:
        provenance = None
        if args.verbose_output:
            provenance = read_provenance(args.ip_json, args.previous_provenance, args.evidence)
            args.provenance_output.write_text(json.dumps(provenance, indent=2) + '\n', encoding='utf-8')
        report = build_report(args.ip_json, verbose_output=args.verbose_output, provenance=provenance, sources=args.sources)
        args.output.write_text(report, encoding='utf-8')
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        parser.exit(1, f'Не удалось сформировать общий отчёт ASN. {error}\n')
