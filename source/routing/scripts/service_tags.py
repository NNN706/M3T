"""Group presentation tags by registrable domain using the bundled PSL.

Only tags change: matchers, address coverage and source attribution are preserved.
PSL source/license are recorded in config/public_suffix_list.dat.
"""
from functools import lru_cache
import ipaddress
from pathlib import Path
import re

PSL = Path(__file__).resolve().parent.parent / 'config/public_suffix_list.dat'

@lru_cache(maxsize=1)
def suffixes():
    exact, wildcard, exceptions = set(), set(), set()
    for line in PSL.read_text().splitlines():
        value = line.strip()
        if not value or value.startswith('//'):
            continue
        target = exceptions if value.startswith('!') else wildcard if value.startswith('*.') else exact
        value = value.removeprefix('!').removeprefix('*.')
        target.add(value.encode('idna').decode('ascii').lower())
    return exact, wildcard, exceptions

@lru_cache(maxsize=8192)
def service_tag(tag):
    try:
        ipaddress.ip_address(tag)
        return tag
    except ValueError:
        pass
    host = tag.rstrip('.').lower()
    if '.' not in host or not re.fullmatch(r'[a-z0-9.-]+', host):
        return tag
    labels = host.split('.')
    if any(not part or part.startswith('-') or part.endswith('-') for part in labels):
        return tag
    # Government services are deliberately grouped under gov.ru, although
    # the PSL treats gov.ru as a public suffix for cookie/security boundaries.
    if host == 'gov.ru' or host.endswith('.gov.ru'):
        return 'gov.ru'
    exact, wildcard, exceptions = suffixes()
    size = 1
    for i in range(len(labels)):
        suffix = '.'.join(labels[i:])
        if suffix in exceptions:
            size = len(labels) - i - 1
            break
        if suffix in exact:
            size = max(size, len(labels) - i)
        if i > 0 and suffix in wildcard:
            size = max(size, len(labels) - i + 1)
    return '.'.join(labels[-(size + 1):]) if len(labels) > size else tag


def group_rules(data, field):
    groups = {}
    for rule in data['rules']:
        if set(rule) != {'ruleTag', field}:
            raise ValueError('Service grouping requires ruleTag/' + field + ' fragments')
        tag = service_tag(rule['ruleTag'])
        groups.setdefault(tag, set()).update(rule[field])
    return {**data, 'rules': [{'ruleTag': tag, field: sorted(values, key=(lambda value: (ipaddress.ip_network(value).version, int(ipaddress.ip_network(value).network_address), ipaddress.ip_network(value).prefixlen)) if field == 'ip' else None)}
                            for tag, values in sorted(groups.items()) if values]}
