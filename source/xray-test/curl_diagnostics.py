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
        f"curl {row['exit']}" if row['exit'] else f"HTTP {row['http']}"
        for row in attempts
    )


def compare(direct, proxied):
    labels = {
        (True, True): 'Оба пути доступны',
        (True, False): 'Ошибка только через Xray',
        (False, True): 'Доступен только через Xray',
        (False, False): 'Ошибка на обоих путях',
    }
    lines = ['## Сравнение curl на одном раннере', '',
             '| Сайт | Напрямую | Через Xray | Итог |',
             '| --- | --- | --- | --- |']
    regressions = False
    for url, plain in direct.items():
        socks = proxied[url]
        outcome = successful(plain), successful(socks)
        regressions |= outcome == (True, False)
        lines.append(f"| {url.replace('|', '%7C')} | {describe(plain)} | {describe(socks)} | {labels[outcome]} |")
    return '\n'.join(lines) + '\n', regressions


def failed_urls(evidence):
    urls = {}
    browser_path = evidence / 'sites.json'
    if browser_path.is_file():
        for row in json.loads(browser_path.read_bytes())['results']:
            if row['required'] and not row['ok']:
                urls[row['url']] = None
    proxy_path = evidence / 'curl-xray.json'
    if proxy_path.is_file():
        for url, attempts in json.loads(proxy_path.read_bytes()).items():
            if not successful(attempts):
                urls[url] = None
    return list(urls)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('required_sites', type=Path)
    parser.add_argument('evidence', type=Path)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--proxy')
    mode.add_argument('--after-failure', action='store_true')
    args = parser.parse_args()
    if args.after_failure:
        urls = failed_urls(args.evidence)
        if not urls:
            print('Нет результатов с ошибкой конкретного сайта для повторного curl.')
            return 0
    else:
        urls = list(dict.fromkeys(row['url'] for row in json.loads(args.required_sites.read_bytes())))
    direct_file = args.evidence / 'curl-direct.json'
    with ThreadPoolExecutor(max_workers=6) as pool:
        results = dict(zip(urls, pool.map(lambda url: probe(url, args.proxy), urls)))
    if args.after_failure:
        (args.evidence / 'curl-direct-after-failure.json').write_text(json.dumps(results, indent=2) + '\n')
        print('\n## Прямой curl после сбоя Xray-проверки\n')
        print('| Сайт | Две попытки без прокси |\n| --- | --- |')
        for url, attempts in results.items():
            print(f"| {url.replace('|', '%7C')} | {describe(attempts)} |")
        return 0
    if args.proxy is None:
        direct_file.write_text(json.dumps(results, indent=2) + '\n')
        return 0
    (args.evidence / 'curl-xray.json').write_text(json.dumps(results, indent=2) + '\n')
    direct = json.loads(direct_file.read_bytes())
    report, regressions = compare(direct, results)
    (args.evidence / 'curl-comparison.md').write_text(report)
    print(report, end='')
    return int(regressions)


if __name__ == '__main__':
    raise SystemExit(main())
