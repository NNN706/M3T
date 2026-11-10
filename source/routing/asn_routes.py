"""BGP.tools exports and per-origin coverage before global CIDR collapse."""
from collections import defaultdict
import csv
import fcntl
from hashlib import sha256
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time


EXPORT_BASE = 'https://bgp.tools'
USER_AGENT = 'M3T routing - https://github.com/NNN706/M3T'
# A sanity check against tiny or partial exports. The sampled table has 1.5M rows.
MIN_TABLE_ROWS = 1_000_000


def asn(value):
    match = re.fullmatch(r'AS(?:N)?([0-9]{1,8})', value, re.I)
    return 'AS' + str(int(match[1])) if match else None


def cached_export(filename, max_age, read):
    cache = Path(os.environ.get('XDG_CACHE_HOME') or Path.home() / '.cache') / 'SubnetResolve' / 'bgp-tools'
    cache.mkdir(parents=True, exist_ok=True)
    target = cache / filename
    with (cache / (filename + '.lock')).open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if target.is_file() and 0 <= time.time() - target.stat().st_mtime < max_age:
            return read(target)
        with tempfile.NamedTemporaryFile(dir=cache, prefix=filename + '.', delete=False) as stream:
            temporary = Path(stream.name)
        try:
            download = subprocess.run(
                ['curl', '--fail', '--silent', '--show-error', '--location',
                 '--proto', '=https', '--proto-redir', '=https',
                 '--retry', '2', '--retry-all-errors', '--retry-max-time', '180',
                 '--connect-timeout', '10', '--max-time', '90', '--user-agent', USER_AGENT,
                 '--output', str(temporary), f'{EXPORT_BASE}/{filename}'],
                capture_output=True, text=True, timeout=280,
            )
            if download.returncode:
                raise RuntimeError(f'BGP.tools {filename}: скачивание не удалось после повторов '
                                   f'(curl {download.returncode}): {download.stderr.strip()}')
            result = read(temporary)
            os.replace(temporary, target)
            return result
        finally:
            temporary.unlink(missing_ok=True)


def table_prefixes(path, origins):
    selected = defaultdict(set)
    families = set()
    count = 0
    with path.open(encoding='utf-8') as stream:
        for count, line in enumerate(stream, 1):
            try:
                if not line.endswith('\n'):
                    raise ValueError('строка не завершена')
                row = json.loads(line)
                origin = row['ASN']
                if type(origin) is not int or not 0 < origin <= 4294967295:
                    raise ValueError('некорректный ASN')
                prefix = ipaddress.ip_network(row['CIDR'], strict=True)
            except (ValueError, KeyError, TypeError) as error:
                raise ValueError(f'BGP.tools table.jsonl, строка {count}: {error}') from error
            families.add(prefix.version)
            if origin in origins:
                selected[origin].add(str(prefix))
    if count < MIN_TABLE_ROWS or families != {4, 6}:
        raise ValueError(f'BGP.tools table.jsonl: неполная таблица, строк {count}, семейства IP {sorted(families)}')
    return selected


class BgpTable:
    """Share one validated parse within a scan without extending export freshness."""

    def __init__(self):
        self.digest = None
        self.snapshot = {}

    def prefixes(self, origins):
        def read(path):
            digest = sha256()
            with path.open('rb') as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                    digest.update(chunk)
            fingerprint = digest.digest()
            if fingerprint != self.digest:
                self.snapshot = table_prefixes(path, range(1, 2**32))
                self.digest = fingerprint
            return {origin: self.snapshot[origin] for origin in origins if origin in self.snapshot}

        return cached_export('table.jsonl', 7200, read)


def asn_names(path, origins):
    with path.open(encoding='utf-8', newline='') as stream:
        rows = csv.DictReader(stream)
        if not rows.fieldnames or not {'asn', 'name'} <= set(rows.fieldnames):
            raise ValueError('BGP.tools asns.csv: отсутствуют колонки asn/name')
        return {row['asn']: row['name'] for row in rows if row['asn'] in origins and row['name']}


def collect(explicit, observations, *, table=None):
    observed = {}
    names = {}
    for row in observations:
        origin = asn(str(row['asn']))
        if origin:
            observed.setdefault(origin, set()).add(row['prefix'])
            if row.get('as_name'):
                names[origin] = row['as_name']
    origins = sorted(set(explicit) | observed.keys(), key=lambda value: int(value[2:]))
    if origins:
        ids = {int(origin[2:]) for origin in origins}
        snapshot = (table.prefixes(ids) if table is not None else
                    cached_export('table.jsonl', 7200, lambda path: table_prefixes(path, ids)))
        unnamed = set(origins) - names.keys()
        if unnamed:
            try:
                names.update(cached_export('asns.csv', 86400, lambda path: asn_names(path, unnamed)))
            except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
                print(f'BGP.tools: не удалось получить названия ASN: {error}', flush=True)
    rules, missing = [], []
    report = ['## Покрытие ASN по снимку BGP.tools', '',
              '| ASN | Название | Источник | Затронуто / всего | Покрытие |',
              '| --- | --- | --- | --- | --- |']
    for origin in origins:
        name = names.get(origin)
        announced = snapshot.get(int(origin[2:]), set())
        direct = origin in explicit
        found = observed.get(origin, set())
        selected = found | announced if direct else found
        if direct:
            rules.append({'ruleTag': origin, 'ip': sorted(announced)})
            if not announced:
                missing.append(origin)
        source = 'Вход' if direct else 'DNS → BGP'
        if direct and found:
            source += ' + DNS → BGP'
        networks = [ipaddress.ip_network(value) for value in selected]
        collapsed = {v: list(ipaddress.collapse_addresses(n for n in networks if n.version == v))
                     for v in (4, 6)}
        targets = [ipaddress.ip_network(value) for value in announced]
        touched = sum(any(n.overlaps(target) for n in collapsed[target.version]) for target in targets)
        full = sum(any(target.subnet_of(n) for n in collapsed[target.version]) for target in targets)
        counts = f'{touched} / {len(targets)}'
        coverage = 'Все' if targets and full == len(targets) else f'Полностью покрыто: {full}'
        label = ' '.join((name or '—').split()).replace('|', '&#124;').replace('<', '&lt;')
        report.append(f'| {origin} | {label} | {source} | {counts} | {coverage} |')
    return rules, missing, '\n'.join(report) + '\n'
