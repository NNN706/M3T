"""Keep Cloudflare IP ranges out of generated direct IP rules."""
from bisect import bisect_left
import csv
import ipaddress
import re

from asn_routes import cached_export, table_prefixes


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

    def ipv4_index(self):
        """Map subnet sizes to their integer network addresses for jq lookups."""
        index = {}
        for network in self.ranges[4]:
            index.setdefault(str(network.num_addresses), {})[str(int(network.network_address))] = True
        return index

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
