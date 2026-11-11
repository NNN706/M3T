"""Compare direct and Xray SOCKS requests from the same runner."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import subprocess


def probe(url, proxy):
    transport = ['--noproxy', '*'] if proxy is None else [
        '--noproxy', '', '--socks5-hostname', proxy,
    ]
    attempts = []
    for _ in range(2):
        response = subprocess.run(
            ['curl', '--disable', *transport, '--silent', '--show-error', '--location',
             '--max-redirs', '10', '--connect-timeout', '10', '--max-time', '20',
             '--output', '/dev/null', '--write-out',
             '%{http_code}\t%{remote_ip}\t%{num_redirects}\t%{time_namelookup}\t'
             '%{time_connect}\t%{time_appconnect}\t%{time_starttransfer}\t%{time_total}',
             '--', url], capture_output=True, text=True,
        )
        keys = ('http', 'remote_ip', 'redirects', 'dns', 'tcp', 'tls', 'first_byte', 'total')
        attempts.append(dict(zip(keys, response.stdout.split('\t'))) | {
            'exit': response.returncode, 'error': response.stderr.strip(),
        })
    return attempts


def successful(attempts):
    return any(row['exit'] == 0 and row['http'].startswith('2') for row in attempts)


def describe(attempts):
    return ' / '.join(
        ({51: 'Ошибка проверки TLS-сертификата', 60: 'Ошибка проверки TLS-сертификата',
          77: 'Ошибка чтения локального хранилища TLS-сертификатов'}.get(row['exit'], f"curl {row['exit']}")
         if row['exit'] else f"HTTP {row['http']}")
        for row in attempts
    )


def compare(direct, proxied):
    labels = {
        (True, True): 'Оба пути доступны',
        (True, False): 'Ошибка только через Xray',
        (False, True): 'Доступен только через Xray',
        (False, False): 'Ошибка на обоих путях',
    }
    return [
        {'url': url, 'direct': describe(plain), 'proxy': describe(proxied[url]),
         'outcome': labels[successful(plain), successful(proxied[url])],
         'regression': successful(plain) and not successful(proxied[url])}
        for url, plain in direct.items()
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('queue', type=Path)
    parser.add_argument('evidence', type=Path)
    parser.add_argument('--proxy')
    args = parser.parse_args()
    profiles = json.loads(args.queue.read_bytes())
    urls = [row['url'] for row in profiles]
    direct_file = args.evidence / 'curl-direct.json'
    with ThreadPoolExecutor(max_workers=15) as pool:
        results = dict(zip(urls, pool.map(lambda url: probe(url, args.proxy), urls)))
    if args.proxy is None:
        direct_file.write_text(json.dumps(results, indent=2) + '\n')
        return 0
    (args.evidence / 'curl-xray.json').write_text(json.dumps(results, indent=2) + '\n')
    comparison = compare(json.loads(direct_file.read_bytes()), results)
    (args.evidence / 'curl-comparison.json').write_text(json.dumps(comparison, indent=2) + '\n')
    required = {row['url'] for row in profiles if row['required']}
    return int(any(row['regression'] and row['url'] in required for row in comparison))


if __name__ == '__main__':
    raise SystemExit(main())
