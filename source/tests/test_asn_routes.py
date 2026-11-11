"""BGP export validation, cache protection and ASN coverage."""
import os
from pathlib import Path
from subprocess import CompletedProcess
import sys
from tempfile import TemporaryDirectory
from unittest.mock import patch
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'routing'))
import asn_routes

TABLE = (
    '{"CIDR":"192.0.2.0/24","ASN":100,"Hits":30}\n'
    '{"CIDR":"2001:db8::/32","ASN":100,"Hits":20}\n'
    '{"CIDR":"198.51.100.0/24","ASN":200,"Hits":25}\n'
)
NAMES = 'asn,name,class,cc\nAS100,Example AS,Unknown,US\n'


def download(command, **kwargs):
    output = Path(command[command.index('--output') + 1])
    output.write_text(NAMES if command[-1].endswith('/asns.csv') else TABLE)
    return CompletedProcess(command, 0, '', '')


with TemporaryDirectory() as directory, patch.dict(os.environ, {'XDG_CACHE_HOME': directory}):
    with patch.object(asn_routes, 'MIN_TABLE_ROWS', 3):
        with patch.object(asn_routes.subprocess, 'run', side_effect=download) as curl:
            observations = [{'asn': 'AS200', 'as_name': 'Observed AS', 'prefix': '198.51.100.0/25'}]
            rules, missing, report = asn_routes.collect({'AS100'}, observations)
            assert rules == [{'ruleTag': 'AS100', 'ip': ['192.0.2.0/24', '2001:db8::/32']}]
            assert not missing
            assert '| AS100 | Example AS | Вход | 2 / 2 | Все |' in report
            assert '| AS200 | Observed AS | DNS → BGP | 1 / 1 | Полностью покрыто: 0 |' in report
            assert asn_routes.collect({'AS100'}, observations) == (rules, missing, report)
            assert curl.call_count == 2

        target = Path(directory) / 'SubnetResolve/bgp-tools/table.jsonl'
        table = asn_routes.BgpTable()
        with patch.object(asn_routes, 'table_prefixes', wraps=asn_routes.table_prefixes) as parse:
            assert table.prefixes({100}) == {100: {'192.0.2.0/24', '2001:db8::/32'}}
            assert table.prefixes({200}) == {200: {'198.51.100.0/24'}}
            assert parse.call_count == 1
            target.write_text(TABLE.replace('198.51.100.0/24', '198.51.100.0/25'))
            assert table.prefixes({200}) == {200: {'198.51.100.0/25'}}
            assert parse.call_count == 2
            target.write_text(TABLE)
        os.utime(target, (1, 1))

        def incomplete(command, **kwargs):
            Path(command[command.index('--output') + 1]).write_text(TABLE[:-1])
            return CompletedProcess(command, 0, '', '')

        with patch.object(asn_routes.subprocess, 'run', side_effect=incomplete):
            try:
                asn_routes.collect({'AS100'}, [])
            except ValueError as error:
                assert 'строка не завершена' in str(error)
            else:
                raise AssertionError('Incomplete snapshot was accepted')
        assert target.read_text() == TABLE

print('PASS BGP.tools dual-stack export, report-only domain coverage, cache reuse and incomplete download rejection')


def sample_prefixes(origins):
    assert origins == {15169, 64500}
    return {
        15169: {'142.250.120.0/24', '142.250.0.0/15', '142.252.0.0/15'},
        64500: {'142.0.0.0/8', '2001:db8::/32'},
    }


routes = [
    {'asn': 'AS15169', 'prefix': '142.250.120.0/24', 'ips': ['142.250.120.154']},
    {'asn': 'AS64500', 'prefix': '2001:db8:1::/48', 'ips': ['2001:db8:1::2']},
    {'asn': 'AS15169', 'prefix': '142.254.0.0/16', 'ips': ['142.254.0.1']},
]
effective = asn_routes.broadest_routes(routes, SimpleNamespace(prefixes=sample_prefixes))
assert [row['prefix'] for row in effective] == ['142.250.0.0/15', '2001:db8::/32', '142.254.0.0/16']
assert [row['ips'] for row in effective] == [row['ips'] for row in routes]
assert routes[0]['prefix'] == '142.250.120.0/24'
print('PASS broadest enclosing announcement of the same ASN; original evidence preserved')
