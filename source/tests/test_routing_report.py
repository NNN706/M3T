"""Report over all published prefixes, including overlaps and shared BGP origins."""
from hashlib import sha256
import json
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / 'routing'))
from routing_report import build_report, read_provenance

with tempfile.TemporaryDirectory() as directory:
    ip_file = Path(directory) / 'IP.json'
    ip_file.write_text(json.dumps({'rules': [
        {'ruleTag': 'legacy', 'ip': ['192.0.2.0/25', '2001:db8::/48']},
        {'ruleTag': 'service.example', 'ip': ['192.0.2.128/25', '198.51.100.0/25']},
    ]}))
    table = Path(directory) / 'table.jsonl'
    table.write_text(''.join(json.dumps({'ASN': origin, 'CIDR': prefix}) + '\n'
                            for origin, prefix in [
        (100, '192.0.2.0/24'), (100, '192.0.2.0/24'), (100, '198.51.100.0/24'),
        (101, '192.0.2.0/24'), (101, '2001:db8::/48'),
        (102, '203.0.113.0/24'),
        (103, '198.51.100.0/24'),
    ]))
    names = Path(directory) / 'asns.csv'
    names.write_text('asn,name\nAS100,"Example | Inc."\nAS101,Other origin\n')
    evidence = ip_file.parent / 'evidence'
    evidence.mkdir()
    (evidence / 'scanner-output-1.json').write_text(json.dumps({'domains': [
        {'domain': 'asset.example', 'results': [
            {'asn': 'AS100', 'prefix': '192.0.2.0/24', 'ips': ['192.0.2.201', '192.0.3.1']},
            {'asn': 'AS103', 'prefix': '198.51.100.0/24', 'ips': ['198.51.100.220']},
        ]},
    ]}))
    (evidence / 'scanner-output-2.json').write_text('{"domains":')
    (evidence / 'dns-checkpoint.json').write_text(json.dumps({
        'resume.example': {'domain': 'resume.example', 'results': [
            {'asn': 'AS101', 'prefix': '2001:db8::/48', 'ips': ['2001:db8::7']},
        ]},
    }))
    previous = ip_file.parent / 'previous.json'
    previous.write_text(json.dumps({'old.example': {'AS100': ['192.0.2.201', '192.0.4.1']}}))
    provenance = read_provenance(ip_file, previous, [evidence])
    assert provenance == {
        'asset.example': {'AS100': ['192.0.2.201']},
        'old.example': {'AS100': ['192.0.2.201']},
        'resume.example': {'AS101': ['2001:db8::7']},
    }, provenance
    verbose = ip_file.parent / 'verbose.md'
    with patch('asn_routes.MIN_TABLE_ROWS', 1), patch(
        'routing_report.cached_export', side_effect=lambda filename, _, read: read(Path(directory) / filename)
    ):
        report = build_report(ip_file, verbose_output=verbose, provenance=provenance)

    assert 'Опубликовано **4**' in report
    assert 'IPv4: **3**, IPv6: **1**' in report
    assert 'анонсы **3** ASN' in report
    assert sha256(ip_file.read_bytes()).hexdigest() in report
    assert '[IP.json](https://github.com/NNN706/M3T/blob/test/source/routing/IP.json)' in report
    assert '| AS100 | Example &#124; Inc. | 2 / 2 |' in report
    assert '| AS101 | Other origin | 2 / 2 |' in report
    assert '| AS103 | — | 1 / 1 |' in report
    assert '| AS102 |' not in report
    assert '| ASN | Название | Затронуто / всего |' in report
    assert 'Полностью покрыто' not in report
    assert all(line.count('|') == 4 for line in report.splitlines() if line.startswith('|'))

    details = verbose.read_text()
    assert '| `192.0.2.0/24` | `192.0.2.0/25`, `192.0.2.128/25` | `asset.example` (`192.0.2.201`), `old.example`' in details
    assert '| `192.0.2.0/24` | `192.0.2.0/25`, `192.0.2.128/25` | Нет наблюдений |' in details
    assert '`resume.example` (`2001:db8::7`)' in details
    assert '198.51.100.220' not in details and '192.0.4.1' not in details

    (evidence / 'IP.json').write_bytes(ip_file.read_bytes())
    status = evidence / 'completeness.json'
    status.write_text('{"mode":"full-refresh","complete":false}')
    assert 'old.example' in read_provenance(ip_file, previous, [evidence])
    status.write_text('{"mode":"full-refresh","complete":true}')
    assert 'old.example' not in read_provenance(ip_file, previous, [evidence])
    (evidence / 'IP.json').write_text('{"rules":[]}')
    assert 'old.example' in read_provenance(ip_file, previous, [evidence])

    ip_file.write_text('{"rules":[]}')
    with patch('routing_report.cached_export') as download:
        assert 'анонсы **0** ASN' in build_report(ip_file)
        download.assert_not_called()

print('PASS overall ASN report: published IPv4/IPv6, CIDR union, multi-origin, partial overlaps and three columns')
