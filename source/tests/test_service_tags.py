"""Registrable service tags preserve exact routing data and original sources."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'routing/scripts'))
from service_tags import service_tag, group_rules

for host, expected in {
    'spb.mts.ru': 'mts.ru', 'sc.gosuslugi.ru': 'gosuslugi.ru',
    'search.gosuslugi.ru': 'gosuslugi.ru', 'nalog.gov.ru': 'gov.ru',
    'nuc-cdp.digital.gov.ru': 'gov.ru', 'lk.megafon.ru': 'megafon.ru',
    'spb.megafon.ru': 'megafon.ru', 'a.service.co.uk': 'service.co.uk',
    'a.alice.github.io': 'alice.github.io', 'b.bob.github.io': 'bob.github.io',
    'a.b.ck': 'a.b.ck', 'a.www.ck': 'www.ck',
    'legacy': 'legacy', 'AS123': 'AS123', 'local networks': 'local networks',
    '192.0.2.1': '192.0.2.1', 'megafon.ru': 'megafon.ru',
}.items():
    assert service_tag(host) == expected, (host, service_tag(host), expected)
for field, values in [('ip', ['85.143.124.0/22', '85.143.160.0/21']),
                      ('domain', ['full:sc.gosuslugi.ru', 'domain:search.gosuslugi.ru'])]:
    original = {'rules': [{'ruleTag': tag, field: [value]} for tag, value in
                          zip(['sc.gosuslugi.ru', 'search.gosuslugi.ru'], values)]}
    result = group_rules(original, field)
    assert result == {'rules': [{'ruleTag': 'gosuslugi.ru', field: sorted(values)}]}
    assert original['rules'][0]['ruleTag'] == 'sc.gosuslugi.ru'
    assert group_rules(result, field) == result
print('PASS service grouping, PSL multi-label/private/wildcard/exception suffixes, unchanged routing values and sources')
