"""Keep Cloudflare destinations out of generated direct rules."""
from bisect import bisect_left
from concurrent.futures import ThreadPoolExecutor
import csv
import ipaddress
import re
import socket

from asn_routes import cached_export, table_prefixes


# The supplied example must stay off direct even when DNS is temporarily unavailable.
EXCLUDED_HOSTS = {'auth.openai.com'}


def cloudflare_origins(path):
    with path.open(encoding='utf-8', newline='') as stream:
        rows = csv.DictReader(stream)
        if not rows.fieldnames or not {'asn', 'name'} <= set(rows.fieldnames):
            raise ValueError('BGP.tools asns.csv: отсутствуют колонки asn/name')
        origins = {int(row['asn'][2:]) for row in rows
                   if re.fullmatch(r'AS[0-9]+', row['asn']) and
                   re.match(r'^Cloudflare\b', row['name'].strip(), re.I)}
    if not {13335, 209242} <= origins:
        raise ValueError('BGP.tools asns.csv: отсутствуют основные ASN Cloudflare')
    return origins


def lookup_addresses(host):
    try:
        return {record[4][0] for record in socket.getaddrinfo(host + '.', None, type=socket.SOCK_STREAM)}
    except socket.gaierror:
        return set()


class CloudflarePolicy:
    def __init__(self, origins, prefixes):
        self.asns = {'AS' + str(origin) for origin in origins}
        networks = [ipaddress.ip_network(prefix) for prefix in prefixes]
        self.ranges = {v: list(ipaddress.collapse_addresses(n for n in networks if n.version == v))
                       for v in (4, 6)}
        self.ends = {v: [int(n.broadcast_address) for n in self.ranges[v]] for v in (4, 6)}

    @classmethod
    def load(cls):
        origins = cached_export('asns.csv', 86400, cloudflare_origins)
        snapshot = cached_export('table.jsonl', 7200, lambda path: table_prefixes(path, origins))
        if not {13335, 209242} <= snapshot.keys():
            raise ValueError('BGP.tools table.jsonl: отсутствуют маршруты основных ASN Cloudflare')
        return cls(origins, set().union(*snapshot.values()))

    def _overlaps(self, network):
        first = int(network.network_address)
        last = int(network.broadcast_address)
        version = network.version
        ranges = self.ranges[version]
        for index in range(bisect_left(self.ends[version], first), len(ranges)):
            candidate = ranges[index]
            if int(candidate.network_address) > last:
                break
            yield candidate

    def _contains(self, address):
        ip = ipaddress.ip_address(address)
        index = bisect_left(self.ends[ip.version], int(ip))
        return index < len(self.ranges[ip.version]) and ip in self.ranges[ip.version][index]

    def excluded_hosts(self, hosts, previous, responses):
        excluded = set(previous) | EXCLUDED_HOSTS
        for host, row in responses.items():
            if any(route.get('asn') in self.asns or
                   any(self._contains(ip) for ip in route.get('ips', []))
                   for route in row['results']):
                excluded.add(host)

        # Supplement Check-Host's IPv4 observations with the runner's A/AAAA
        # answers, including hosts from older rules without per-host BGP records.
        candidates = sorted(set(hosts) - excluded)
        with ThreadPoolExecutor(max_workers=24) as pool:
            for host, addresses in zip(candidates, pool.map(lookup_addresses, candidates)):
                if any(self._contains(ip) for ip in addresses):
                    excluded.add(host)
        return excluded

    def filter_rules(self, sources, domains, excluded):
        rules = []
        for rule in sources['rules']:
            if rule['ruleTag'] in self.asns:
                continue
            prefixes = []
            for prefix in rule['ip']:
                network = ipaddress.ip_network(prefix)
                pieces = [network]
                for denied in self._overlaps(network):
                    remaining = []
                    for piece in pieces:
                        if piece.subnet_of(denied):
                            continue
                        remaining.extend(piece.address_exclude(denied) if denied.subnet_of(piece) else [piece])
                    pieces = remaining
                prefixes.extend(str(piece) for piece in pieces)
            if prefixes:
                rules.append({**rule, 'ip': prefixes})

        # Xray domain: matches the hostname and all its descendants. Narrow any
        # ancestor of an excluded host to an exact hostname.
        ancestors = {host.split('.', offset)[-1] for host in excluded
                     for offset in range(1, host.count('.'))}
        domain_rules = []
        for rule in domains['rules']:
            matchers = set()
            for matcher in rule['domain']:
                kind, host = matcher.split(':', 1)
                if host in excluded:
                    continue
                if kind == 'domain' and host in ancestors:
                    kind = 'full'
                matchers.add(f'{kind}:{host}')
            if matchers:
                domain_rules.append({**rule, 'domain': sorted(matchers)})
        return {**sources, 'rules': rules}, {'rules': domain_rules}
