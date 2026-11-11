import importlib.util
import json
import sys
from tempfile import TemporaryDirectory
from pathlib import Path
import subprocess
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('diagnostics', Path(__file__).parents[1] / 'curl_diagnostics.py')
diagnostics = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diagnostics)


def probe(http, status=0):
    return [{'http': str(http), 'exit': status}]


urls = ['https://both.example', 'https://blocked.example', 'https://proxy.example', 'https://offline.example']
direct = dict(zip(urls, [probe(200), probe(200), probe(403), probe(0, 28)]))
proxied = dict(zip(urls, [probe(200), probe(403), probe(204), probe(0, 28)]))
report = diagnostics.compare(direct, proxied)
assert [row['outcome'] for row in report] == [
    'Оба пути доступны', 'Ошибка только через Xray', 'Доступен только через Xray', 'Ошибка на обоих путях',
]
assert [row['url'] for row in report if row['regression']] == [urls[1]]
assert 'TLS-сертификата' in diagnostics.describe(probe(0, 60))

response = subprocess.CompletedProcess([], 0, '200\t127.0.0.1\t0\t0\t0\t0\t0\t0', '')
with patch.object(diagnostics.subprocess, 'run', return_value=response) as curl:
    direct_result = diagnostics.probe(urls[0], None)
    proxied_result = diagnostics.probe(urls[0], '127.0.0.1:1080')
    assert len(direct_result) == len(proxied_result) == 2
    assert [call.args[0][2:4] for call in curl.call_args_list] == [
        ['--noproxy', '*'], ['--noproxy', '*'], ['--noproxy', ''], ['--noproxy', ''],
    ]
    assert '--socks5-hostname' in curl.call_args.args[0]
    assert diagnostics.successful(proxied_result)
print('PASS direct and SOCKS curl use comparable settings and report all four outcomes')

with TemporaryDirectory() as directory:
    evidence = Path(directory)
    queue = evidence / 'queue.json'
    queue.write_text(json.dumps([{'url': url, 'required': url == urls[0]} for url in urls]))
    with patch.object(sys, 'argv', ['curl_diagnostics.py', str(queue), directory]), \
            patch.object(diagnostics, 'probe', side_effect=lambda url, _: direct[url]) as call:
        assert diagnostics.main() == 0
        assert {item.args for item in call.call_args_list} == {(url, None) for url in urls}
    proxy = '127.0.0.1:1080'
    with patch.object(sys, 'argv', ['curl_diagnostics.py', str(queue), directory, '--proxy', proxy]), \
            patch.object(diagnostics, 'probe', side_effect=lambda url, _: proxied[url]) as call:
        assert diagnostics.main() == 0
        assert {item.args for item in call.call_args_list} == {(url, proxy) for url in urls}
    assert json.loads((evidence / 'curl-comparison.json').read_text()) == report

    queue.write_text(json.dumps([{'url': url, 'required': url == urls[1]} for url in urls]))
    with patch.object(sys, 'argv', ['curl_diagnostics.py', str(queue), directory, '--proxy', proxy]), \
            patch.object(diagnostics, 'probe', side_effect=lambda url, _: proxied[url]):
        assert diagnostics.main() == 1
print('PASS curl checks both paths for the entire queue and gates only required regressions')
