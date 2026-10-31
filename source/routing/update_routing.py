"""Scan services and atomically write deduplicated Xray rule fragments (Python stdlib)."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import tempfile
from urllib.parse import urlsplit


def services(path):
    result = []
    seen = set()
    for line in path.read_text().splitlines():
        line = line.split('#', 1)[0].strip()
        if not line:
            continue
        for value in line.split():
            url = urlsplit(value if '://' in value else 'https://' + value)
            if url.scheme not in ('http', 'https') or not url.hostname or url.username or url.password:
                raise ValueError('Expected a domain or HTTP(S) URL without credentials')
            host = url.hostname.lower().rstrip('.')
            if host not in seen:
                seen.add(host)
                result.append((host, value))
    if not result:
        raise ValueError('sites.txt is empty: add one service domain or URL per line')
    return result


def compact_rules(data, expected):
    rules = data['rules']
    if not isinstance(rules, list) or [r['ruleTag'] for r in rules] != sorted(expected):
        raise ValueError('Unexpected service tags in scanner result')
    result = []
    for rule in rules:
        if not isinstance(rule['ip'], list) or not rule['ip']:
            raise ValueError('No prefixes for service ' + rule['ruleTag'])
        networks = [ipaddress.IPv4Network(value, strict=True) for value in rule['ip']]
        result.append({'ruleTag': rule['ruleTag'], 'ip': [str(n) for n in ipaddress.collapse_addresses(networks)]})
    return {'rules': result}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    root = Path(__file__).resolve().parent
    parser.add_argument('--sites', type=Path, default=root / 'sites.txt')
    parser.add_argument('--output', type=Path, default=root / 'IP.txt')
    parser.add_argument('--scanner', type=Path, default=root.parent / 'SubnetResolve.sh')
    args = parser.parse_args()
    entries = services(args.sites)
    scan = subprocess.run(['bash', str(args.scanner), '-parse', '-rules', '-s', '--', *[value for _, value in entries]],
                          stdout=subprocess.PIPE, text=True, timeout=6600)
    if scan.returncode:
        raise RuntimeError('Scan incomplete or failed; existing IP.txt retained. See stderr above.')
    result = compact_rules(json.loads(scan.stdout), [host for host, _ in entries])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', dir=args.output.parent, delete=False) as stream:
            temporary = stream.name
            json.dump(result, stream, ensure_ascii=False, indent=2)
            stream.write('\n')
        os.replace(temporary, args.output)
    finally:
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)


if __name__ == '__main__':
    main()
