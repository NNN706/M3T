"""Narrow selected ASN IPv4 ranges to observed DNS /24s, never enumerate a whole ASN."""
import ipaddress
import re
from pathlib import Path


def read_limits(path):
    result = {}
    for number, line in enumerate(path.read_text().splitlines(), 1):
        value = line.split('#', 1)[0].strip()
        if not value:
            continue
        match = re.fullmatch(r'AS(?:N)?([0-9]{1,10})\s+/([0-9]{1,2})', value, re.I)
        if not match or not 0 < int(match[1]) < 2**32 or not 1 <= int(match[2]) <= 32:
            raise ValueError(f'{path.name}:{number}: ожидается ASN и IPv4-маска, например AS24940 /24')
        origin, length = int(match[1]), int(match[2])
        if origin in result:
            raise ValueError(f'{path.name}:{number}: ASN AS{origin} указан повторно')
        result[origin] = length
    return result


def subtract(network, cut):
    if not network.overlaps(cut):
        return [network]
    if network.subnet_of(cut):
        return []
    return list(network.address_exclude(cut))


class PrefixLimits:
    def __init__(self, lengths, snapshot):
        self.lengths = lengths
        self.ranges = {origin: list(ipaddress.collapse_addresses(
            network for network in map(ipaddress.ip_network, snapshot.get(origin, [])) if network.version == 4))
            for origin in lengths}
        self.unobserved = []

    @classmethod
    def load(cls, path, table):
        lengths = read_limits(path)
        return cls(lengths, table.prefixes(set(lengths)) if lengths else {})

    def signature(self):
        return {str(origin): [length, [str(n) for n in self.ranges[origin]]]
                for origin, length in sorted(self.lengths.items())}

    def filter_rules(self, data, domains, provenance):
        hosts = {rule['ruleTag']: {value.split(':', 1)[1] for value in rule['domain']}
                 for rule in domains['rules']}
        result = []
        for rule in data['rules']:
            tag = rule['ruleTag']
            selected_hosts = (provenance if tag == 'legacy' or re.fullmatch(r'AS[0-9]+', tag)
                              else hosts.get(tag, {tag}))
            addresses = {origin: set() for origin in self.lengths}
            for host in selected_hosts:
                for origin, values in provenance.get(host, {}).items():
                    if not re.fullmatch(r'AS[0-9]+', origin) or int(origin[2:]) not in addresses:
                        continue
                    for value in values:
                        address = ipaddress.ip_address(value)
                        if address.version == 4:
                            addresses[int(origin[2:])].add(address)
            kept = []
            for value in rule['ip']:
                original = ipaddress.ip_network(value)
                pieces = [original]
                replacements = []
                if original.version == 4:
                    for origin, length in self.lengths.items():
                        if original.prefixlen >= length:
                            continue
                        for announced in self.ranges[origin]:
                            if not original.overlaps(announced):
                                continue
                            pieces = [part for piece in pieces for part in subtract(piece, announced)]
                            observed = [ip for ip in addresses[origin] if ip in original and ip in announced]
                            for address in observed:
                                narrowed = ipaddress.ip_network(f'{address}/{length}', strict=False)
                                # A more-specific ASN boundary must never be enlarged.
                                replacements.append(narrowed if narrowed.subnet_of(announced) else announced)
                            if not observed:
                                self.unobserved.append({'ruleTag': tag, 'prefix': value, 'asn': f'AS{origin}'})
                kept.extend(pieces + replacements)
            prefixes = [str(n) for version in (4, 6)
                        for n in ipaddress.collapse_addresses(n for n in kept if n.version == version)]
            if prefixes:
                result.append({'ruleTag': tag, 'ip': prefixes})
        return {**data, 'rules': result}

    def finalize(self, data):
        """Prevent adjacent observed /24s being collapsed back to a wider mask."""
        rules = []
        for rule in data['rules']:
            networks = []
            for value in rule['ip']:
                pieces = [ipaddress.ip_network(value)]
                for origin, length in self.lengths.items():
                    for announced in self.ranges[origin]:
                        next_pieces = []
                        for piece in pieces:
                            if piece.version != 4 or piece.prefixlen >= length or not piece.overlaps(announced):
                                next_pieces.append(piece)
                                continue
                            inside = piece if piece.subnet_of(announced) else announced
                            next_pieces.extend(subtract(piece, announced))
                            next_pieces.extend(inside.subnets(new_prefix=length)
                                               if inside.prefixlen < length else [inside])
                        pieces = next_pieces
                networks.extend(pieces)
            rules.append({'ruleTag': rule['ruleTag'], 'ip': [str(n) for n in sorted(set(networks),
                          key=lambda n: (n.version, int(n.network_address), n.prefixlen))]})
        return {**data, 'rules': rules}


def merge_observations(previous, responses):
    result = {host: {origin: set(values) for origin, values in origins.items()}
              for host, origins in previous.items()}
    for host, row in responses.items():
        if row.get('complete') is True:
            result[host] = {}
        for route in row.get('results', []):
            origin = route.get('asn')
            if not origin:
                continue
            network = ipaddress.ip_network(route['prefix'])
            result.setdefault(host, {}).setdefault(origin, set()).update(
                value for value in route.get('ips', []) if ipaddress.ip_address(value) in network)
    return result
