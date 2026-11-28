"""Apply the configured ASN exclusions to generated direct rules."""
from bisect import bisect_left
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import re
from pathlib import Path
import json
import subprocess
import sys
import time

from asn_routes import cached_export, table_prefixes


EXCLUDE_FILE = Path(__file__).resolve().parent.parent / 'exclude.txt'


def read_excluded_asns(path):
    origins = set()
    for number, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
        value = line.split('#', 1)[0].strip()
        if not value:
            continue
        match = re.fullmatch(r'AS(?:N)?([0-9]{1,10})', value, re.I)
        if not match or not 0 < int(match[1]) < 2**32:
            raise ValueError(f'{path.name}:{number}: некорректный ASN {value!r}')
        origins.add(int(match[1]))
    return origins


def lookup_addresses(host):
    # getaddrinfo has no per-call timeout. Isolate it so a resolver stall cannot
    # keep the publishing process (or its executor threads) alive indefinitely.
    code = ('import json,socket,sys; '
            'print(json.dumps(list({r[4][0] for r in socket.getaddrinfo('
            'sys.argv[1],None,type=socket.SOCK_STREAM)})))')
    try:
        reply = subprocess.run([sys.executable, '-c', code, host + '.'],
                               capture_output=True, text=True, timeout=2, check=True)
        return set(json.loads(reply.stdout))
    except (subprocess.SubprocessError, OSError, ValueError):
        return set()


class ExclusionPolicy:
    def __init__(self, origins, prefixes):
        self.asns = {'AS' + str(origin) for origin in origins}
        networks = [ipaddress.ip_network(prefix) for prefix in prefixes]
        self.ranges = {v: list(ipaddress.collapse_addresses(n for n in networks if n.version == v))
                       for v in (4, 6)}
        self.ends = {v: [int(n.broadcast_address) for n in self.ranges[v]] for v in (4, 6)}

    @classmethod
    def load(cls, path=EXCLUDE_FILE, *, table=None):
        origins = read_excluded_asns(path)
        if not origins:
            return cls(set(), set())
        snapshot = (table.prefixes(origins) if table is not None else
                    cached_export('table.jsonl', 7200, lambda path: table_prefixes(path, origins)))
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

    def ipv4_index(self):
        """Map subnet sizes to their integer network addresses for jq lookups."""
        index = {}
        for network in self.ranges[4]:
            index.setdefault(str(network.num_addresses), {})[str(int(network.network_address))] = True
        return index

    def excluded_domains(self, hosts, previous, responses, *, deadline=None):
        excluded = set(previous)
        self.unchecked_domains = set()
        if not self.asns:
            return excluded
        for host, row in responses.items():
            if row.get('excluded_ips') or any(route.get('asn') in self.asns for route in row['results']):
                excluded.add(host)
        # WHOIS/exclusion-index evidence already answered the ASN question.
        verified = {host for host, row in responses.items()
                    if row.get('results') and all(route.get('asn') for route in row['results'])}
        final_no_a = {host for host, row in responses.items()
                      if not row.get('results') and not row.get('excluded_ips') and row.get('errors')
                      and all(error.get('check_host') for error in row['errors'])}
        candidates = sorted(set(hosts) - excluded - verified - final_no_a)
        self.unchecked_domains = set(candidates)
        with ThreadPoolExecutor(max_workers=24) as pool:
            # Submit at most one cohort at a time; never queue half a million
            # socket calls that executor shutdown would then wait to finish.
            for start in range(0, len(candidates), 24):
                if deadline is not None and time.monotonic() >= deadline:
                    break
                cohort = candidates[start:start + 24]
                for host, addresses in zip(cohort, pool.map(lookup_addresses, cohort)):
                    self.unchecked_domains.discard(host)
                    for address in addresses:
                        ip = ipaddress.ip_address(address)
                        version = ip.version
                        index = bisect_left(self.ends[version], int(ip))
                        if index < len(self.ranges[version]) and ip in self.ranges[version][index]:
                            excluded.add(host)
                            break
        return excluded

    def filter_domain_rules(self, domains, excluded):
        # A suffix rule would still route an excluded subdomain. Preserve only
        # the exact hostname of an ancestor in that case.
        ancestors = {host.split('.', offset)[-1] for host in excluded
                     for offset in range(1, host.count('.'))}
        rules = []
        for rule in domains['rules']:
            matchers = set()
            for matcher in rule['domain']:
                kind, host = matcher.split(':', 1)
                if host not in excluded:
                    matchers.add(f'{"full" if host in ancestors else kind}:{host}')
            if matchers:
                rules.append({**rule, 'domain': sorted(matchers)})
        return {'rules': rules}

    def filter_ip_rules(self, sources):
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

        return {**sources, 'rules': rules}
