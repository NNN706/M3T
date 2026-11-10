import importlib.util
import io
import json
import sys
from contextlib import redirect_stdout
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
report, failed = diagnostics.compare(direct, proxied)
assert failed
assert [line.split(' | ')[-1][:-2] for line in report.splitlines()[-4:]] == [
    'Оба пути доступны', 'Ошибка только через Xray', 'Доступен только через Xray', 'Ошибка на обоих путях',
]
assert not diagnostics.compare({urls[3]: direct[urls[3]]}, {urls[3]: proxied[urls[3]]})[1]

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
    assert diagnostics.failed_urls(evidence) == []
    (evidence / 'sites.json').write_text(json.dumps({'results': [
        {'url': urls[0], 'required': True, 'ok': True},
        {'url': urls[1], 'required': True, 'ok': False},
        {'url': urls[2], 'required': False, 'ok': False},
    ]}))
    (evidence / 'curl-xray.json').write_text(json.dumps(proxied))
    (evidence / 'curl-direct.json').write_text(json.dumps(direct))
    output = io.StringIO()
    with patch.object(sys, 'argv', ['curl_diagnostics.py', 'unused.json', directory, '--after-failure']), \
            patch.object(diagnostics, 'probe', return_value=probe(200)) as call, redirect_stdout(output):
        assert diagnostics.main() == 0
    assert {item.args for item in call.call_args_list} == {(urls[1], None), (urls[3], None)}
    assert list(json.loads((evidence / 'curl-direct-after-failure.json').read_text())) == [urls[1], urls[3]]
    assert 'HTTP 200' in output.getvalue()
    assert json.loads((evidence / 'curl-direct.json').read_text()) == direct
print('PASS post-failure curl retries only failed URLs without proxy and preserves baseline')
