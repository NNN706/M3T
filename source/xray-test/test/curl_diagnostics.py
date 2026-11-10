import importlib.util
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
