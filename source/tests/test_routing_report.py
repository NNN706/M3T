"""Report over all published prefixes, including overlaps and shared BGP origins."""
from hashlib import sha256
import json
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / 'routing'))
from routing_report import build_report

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
    with patch('asn_routes.MIN_TABLE_ROWS', 1), patch(
        'routing_report.cached_export', side_effect=lambda filename, _, read: read(Path(directory) / filename)
    ):
        report = build_report(ip_file)

    assert 'Опубликовано **4**' in report
    assert 'IPv4: **3**, IPv6: **1**' in report
    assert 'анонсы **3** ASN' in report
    assert sha256(ip_file.read_bytes()).hexdigest() in report
    assert '| AS100 | Example &#124; Inc. | 2 / 2 | Полностью покрыто: 1 |' in report
    assert '| AS101 | Other origin | 2 / 2 | Все |' in report
    assert '| AS103 | — | 1 / 1 | Полностью покрыто: 0 |' in report
    assert '| AS102 |' not in report

    ip_file.write_text('{"rules":[]}')
    with patch('routing_report.cached_export') as download:
        assert 'анонсы **0** ASN' in build_report(ip_file)
        download.assert_not_called()

print('PASS overall ASN report: published IPv4/IPv6, CIDR union, multi-origin, partial and full coverage')
