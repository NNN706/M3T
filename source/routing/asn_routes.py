"""RIPE RIS announcements and per-origin coverage before global CIDR collapse."""
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import json
import re
from urllib.request import urlopen


def asn(value):
    match = re.fullmatch(r'AS(?:N)?([0-9]{1,8})', value, re.I)
    return 'AS' + str(int(match[1])) if match else None


def fetch(endpoint, origin, extra=''):
    with urlopen(f'https://stat.ripe.net/data/{endpoint}/data.json?resource={origin}{extra}', timeout=15) as response:
        payload = json.load(response)
    if payload['status'] != 'ok':
        raise ValueError('RIPEstat returned an unsuccessful response')
    return payload['data']


def lookup(origin, name):
    try:
        data = fetch('announced-prefixes', origin, '&min_peers_seeing=1')
        end = data['query_endtime']
        prefixes = {row['prefix'] for row in data['prefixes']
                    if any(t['starttime'] <= end <= t['endtime'] for t in row['timelines'])}
        for value in prefixes:
            ipaddress.ip_network(value, strict=True)
    except (OSError, ValueError, KeyError, TypeError) as error:
        return name, None, str(error)
    if not name:
        try:
            name = fetch('as-overview', origin).get('holder')
        except (OSError, ValueError, KeyError, TypeError):
            pass
    return name, prefixes, None


def collect(explicit, observations):
    observed = {}
    names = {}
    for row in observations:
        origin = asn(str(row['asn']))
        if origin:
            observed.setdefault(origin, set()).add(row['prefix'])
            if row.get('as_name'):
                names[origin] = row['as_name']
    origins = sorted(set(explicit) | observed.keys(), key=lambda value: int(value[2:]))
    rules, missing = [], []
    report = ['## Покрытие ASN по данным RIPE RIS', '',
              '| ASN | Название | Источник | Затронуто / всего | Покрытие |',
              '| --- | --- | --- | --- | --- |']
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = pool.map(lambda origin: lookup(origin, names.get(origin)), origins)
        for origin, (name, announced, error) in zip(origins, results):
            direct = origin in explicit
            found = observed.get(origin, set())
            selected = found | ((announced or set()) if direct else set())
            if direct:
                rules.append({'ruleTag': origin, 'ip': sorted(announced or ())})
                if not announced:
                    missing.append(origin)
            source = 'Вход' if direct else 'DNS → BGP'
            if direct and found:
                source += ' + DNS → BGP'
            coverage = 'Общее число неизвестно'
            counts = f'{len(selected)} / ?'
            if announced is not None:
                networks = [ipaddress.ip_network(value) for value in selected]
                collapsed = {v: list(ipaddress.collapse_addresses(n for n in networks if n.version == v))
                             for v in (4, 6)}
                targets = [ipaddress.ip_network(value) for value in announced]
                touched = sum(any(n.overlaps(target) for n in collapsed[target.version]) for target in targets)
                full = sum(any(target.subnet_of(n) for n in collapsed[target.version]) for target in targets)
                counts = f'{touched} / {len(targets)}'
                coverage = 'Все' if targets and full == len(targets) else f'Полностью покрыто: {full}'
            if error:
                print(f'{origin}: RIPEstat: {error}')
            label = ' '.join((name or '—').split()).replace('|', '&#124;').replace('<', '&lt;')
            report.append(f'| {origin} | {label} | {source} | {counts} | {coverage} |')
    return rules, missing, '\n'.join(report) + '\n'
