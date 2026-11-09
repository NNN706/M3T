"""Summarize ASN coverage of the complete published IP.json."""
import argparse
from bisect import bisect_left
from collections import Counter
from hashlib import sha256
import ipaddress
import json
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
        touched = 0
        for prefix in announced:
            network = ipaddress.ip_network(prefix)
            starts, ends = coverage[network.version]
            first, last = int(network.network_address), int(network.broadcast_address)
            index = bisect_left(ends, first)
            if index < len(starts) and starts[index] <= last:
                touched += 1
        if touched:
            rows['AS' + str(origin)] = (touched, len(announced))
    return rows


def build_report(path):
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
        'Источник правил — [IP.json](IP.json). '
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
        report.append(f'| {origin} | {name} | {touched} / {total} |')
    return '\n'.join(report) + '\n'


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ip_json', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    try:
        args.output.write_text(build_report(args.ip_json), encoding='utf-8')
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        parser.exit(1, f'Не удалось сформировать общий отчёт ASN. {error}\n')
