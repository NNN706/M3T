"""Scan services and atomically write deduplicated Xray rule fragments (Python stdlib)."""
import argparse
from bisect import bisect_right
from collections import Counter
from contextlib import ExitStack
from hashlib import sha256
import ipaddress
import json
import os
import re
from shutil import copyfile
from pathlib import Path
import subprocess
import tempfile
import time
import sys
from urllib.parse import urlsplit


def services(path, parse_asn=None):
    result = []
    seen = set()
    for line in path.read_text().splitlines():
        line = line.split('#', 1)[0].strip()
        if not line:
            continue
        for value in line.split():
            origin = parse_asn(value) if parse_asn else None
            if origin:
                if origin not in seen:
                    seen.add(origin)
                    result.append((origin, value))
                continue
            url = urlsplit(value if '://' in value else 'https://' + value)
            if url.scheme not in ('http', 'https') or not url.hostname or url.username or url.password:
                raise ValueError('Expected a domain or HTTP(S) URL without credentials')
            host = url.hostname.lower().rstrip('.')
            key = value if host == 'bgp.he.net' else host
            if key not in seen:
                seen.add(key)
                result.append((host, value))
    return result


def validate_rule_tags(data, expected, context):
    rules = data.get('rules') if isinstance(data, dict) else None
    if not isinstance(rules, list):
        raise ValueError(f'{context}: поле rules должно быть массивом')
    tags = []
    for index, rule in enumerate(rules):
        tag = rule.get('ruleTag') if isinstance(rule, dict) else None
        if not isinstance(tag, str) or not tag.strip():
            raise ValueError(f'{context}: rules[{index}].ruleTag должен быть непустой строкой, получено {tag!r}')
        tags.append(tag)

    counts = Counter(tags)
    required = set(expected)
    issues = []
    for label, values in (
        ('нет тегов', sorted(required - counts.keys())),
        ('лишние теги', sorted(counts.keys() - required)),
        ('повторяющиеся теги', sorted(tag for tag, count in counts.items() if count > 1)),
    ):
        if values:
            issues.append(f'{label}: {", ".join(map(repr, values))}')
    if issues:
        raise ValueError(f'{context}: ' + '; '.join(issues))
    if tags != sorted(tags):
        raise ValueError(f'{context}: ruleTag должны идти по алфавиту, получено {tags!r}')
    return rules


def compact_rules(data, expected, dual_stack=False):
    rules = validate_rule_tags(data, expected, 'Правила IP')
    result = []
    for rule in rules:
        if not isinstance(rule['ip'], list):
            raise ValueError('No prefixes for service ' + rule['ruleTag'])
        networks = [(ipaddress.ip_network if dual_stack else ipaddress.IPv4Network)(value, strict=True) for value in rule['ip']]
        result.append({'ruleTag': rule['ruleTag'], 'ip': [str(n) for version in (4, 6) for n in ipaddress.collapse_addresses(n for n in networks if n.version == version)]})
    return {'rules': result}


def redistribute_legacy(data):
    """Move only whole legacy CIDRs fully covered by named service observations."""
    named = [ipaddress.ip_network(value) for rule in data['rules'] if rule['ruleTag'] != 'legacy'
             for value in rule['ip']]
    cuts = {v: list(ipaddress.collapse_addresses(n for n in named if n.version == v)) for v in (4, 6)}
    rules = []
    for rule in data['rules']:
        if rule['ruleTag'] != 'legacy':
            rules.append(rule)
            continue
        networks = [ipaddress.ip_network(value) for value in rule['ip']]
        remaining = [network for network in networks
                     if not any(network.subnet_of(cut) for cut in cuts[network.version])]
        if remaining:
            rules.append({'ruleTag': 'legacy', 'ip': [str(n) for n in sorted(set(remaining),
                          key=lambda n: (n.version, int(n.network_address), n.prefixlen))]})
    return {**data, 'rules': sorted(rules, key=lambda rule: rule['ruleTag'])}


def format_manual_ips(prefixes):
    local_blocks = [ipaddress.ip_network(value) for value in (
        '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
        '172.16.0.0/12', '192.0.0.0/24', '192.168.0.0/16', '198.18.0.0/15',
        '224.0.0.0/4', '240.0.0.0/4', '::/128', '::1/128', 'fc00::/7', 'fe80::/10', 'ff00::/8')]
    groups = {True: [], False: []}
    networks = [ipaddress.ip_network(value) for value in prefixes]
    for network in sorted(set(networks), key=lambda n: (n.version, int(n.network_address), n.prefixlen)):
        local = any(network.version == block.version and network.subnet_of(block) for block in local_blocks)
        groups[local].append(str(network))
    return ('# Ручные подсети direct; ASN-исключения применяются автоматически.\n'
            '# Целиком найденные у сервисов блоки переносятся из этого списка в их ruleTag.\n\n'
            '#### Локальные подсети\n' + '\n'.join(groups[True]) + '\n\n'
            '#### Остальные подсети\n' + '\n'.join(groups[False]) + '\n')


def global_rules(data):
    """Exact union across tags; prefer a named service over legacy for storage."""
    data = redistribute_legacy(data)
    tagged = []
    for rule in data['rules']:
        if set(rule) != {'ruleTag', 'ip'}:
            raise ValueError('Global IP grouping accepts only ruleTag/ip fragments')
        for value in rule['ip']:
            tagged.append((rule['ruleTag'], ipaddress.ip_network(value, strict=True)))
    collapsed = [n for version in (4,6) for n in ipaddress.collapse_addresses(n for _,n in tagged if n.version==version)]
    groups = {}
    for version in (4, 6):
        networks = [network for network in collapsed if network.version == version]
        starts = [int(network.network_address) for network in networks]
        owners = {}
        for tag, original in tagged:
            if original.version != version:
                continue
            index = bisect_right(starts, int(original.network_address)) - 1
            if index < 0 or not original.subnet_of(networks[index]):
                raise ValueError('Prefix is outside collapsed coverage')
            owners[index] = min(owners.get(index, tag), tag, key=lambda owner: (owner == 'legacy', owner))
        for index, network in enumerate(networks):
            groups.setdefault(owners[index], []).append(str(network))
    result = {'rules':[{'ruleTag':tag, 'ip':groups[tag]} for tag in sorted(groups)]}
    if data.get('ipv4_prefix_limits'):
        from prefix_limits import PrefixLimits
        signature = data['ipv4_prefix_limits']
        limits = PrefixLimits({int(k): v[0] for k, v in signature.items()},
                              {int(k): v[1] for k, v in signature.items()})
        result = limits.finalize(result)
    # Independent integer interval check, not another call to collapse_addresses.
    def coverage(networks):
        merged = []
        for version,lo,hi in sorted((n.version,int(n.network_address),int(n.broadcast_address)) for n in networks):
            if merged and merged[-1][0]==version and lo<=merged[-1][2]+1:
                merged[-1]=(version,merged[-1][1],max(hi,merged[-1][2]))
            else:
                merged.append((version,lo,hi))
        return merged
    output = [ipaddress.ip_network(value) for rule in result['rules'] for value in rule['ip']]
    if coverage(n for _,n in tagged) != coverage(output):
        raise ValueError('Global grouping changed address coverage')
    ordered = sorted(output, key=lambda n:(n.version,int(n.network_address)))
    if any(a.version==b.version and int(a.broadcast_address)>=int(b.network_address) for a,b in zip(ordered,ordered[1:])):
        raise ValueError('Duplicate or overlapping output prefixes')
    return result


def domain_rules(data, expected, *, include_seed=True):
    rules = validate_rule_tags(data, expected, 'Правила доменов')
    result = []
    for rule in rules:
        values = rule.get('domain', ['domain:' + rule['ruleTag']] if include_seed else None)
        if not isinstance(values, list):
            raise ValueError('Expected domain array')
        matchers = {'domain:' + rule['ruleTag']} if include_seed else set()
        for value in values:
            if not isinstance(value, str) or not value.startswith(('domain:', 'full:')):
                raise ValueError('Invalid domain matcher')
            kind, host = value.split(':', 1)
            host = host.lower().rstrip('.')
            if len(host)>253 or len(host.split('.'))<2 or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in host.split('.')):
                raise ValueError('Invalid domain matcher')
            matchers.add(f'{kind}:{host}')
        result.append({'ruleTag':rule['ruleTag'], 'domain':sorted(matchers)})
    return {'rules':result}


def apply_manual_rules(sources, manual):
    groups = {rule['ruleTag']: set(rule['ip']) for rule in sources['rules']}
    for rule in manual['rules']:
        groups.setdefault(rule['ruleTag'], set()).update(rule['ip'])
    result = {**sources, 'rules': [{'ruleTag': tag, 'ip': sorted(values)}
                                  for tag, values in sorted(groups.items())]}
    if manual['rules']:
        result['manual_rules'] = manual['rules']
    return result


def routing_fingerprint(paths):
    return {name: sha256(path.read_bytes()).hexdigest() if path.exists() else None
            for name, path in paths.items()}


def incremental_update(args, entries, explicit, collect, exclusion=None, *, table=None):
    """Workflow mode. Append verified discoveries to the published baseline."""
    resume = getattr(args, 'resume', None)
    full_refresh = getattr(args, 'full_refresh', False)
    # Share the scan budget with Chromium and reserve time for ASN export and
    # writing partial results before the workflow's hard timeout.
    deadline = time.monotonic() + (13800 if full_refresh else 5400)
    outputs = {'IP.json': args.output, 'domains.json': args.domains_output, 'sources.json': args.sources_output}
    invalid = sorted(host for host, _ in entries if len(host) > 253 or '.' not in host
                     or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
                                for label in host.split('.')))
    for host in invalid:
        print(f'Некорректное DNS-имя в sites.txt: {host!r}. Остальные записи будут обработаны.', file=sys.stderr)
    entries = [(host, url) for host, url in entries if host not in invalid]
    manual_path = getattr(args, 'manual_rules', None)
    manual_ips = getattr(args, 'manual_ips', None)
    limits = getattr(args, 'prefix_limit_policy', None)
    previous_provenance = getattr(args, 'previous_provenance', None)
    raw_manual_ips = []
    if manual_ips is not None:
        outputs['ip.txt'] = manual_ips
    manual = {'rules': []}
    if manual_path is not None and manual_path.is_file():
        if manual_path.suffix == '.json':
            manual = json.loads(manual_path.read_bytes())
        else:
            tag = None
            groups = {}
            for line_number, line in enumerate(manual_path.read_text().splitlines(), 1):
                if line.startswith('#### '):
                    tag = line[5:].strip()
                    if not tag or tag == 'legacy' or tag in groups:
                        raise ValueError(f'{manual_path.name}, строка {line_number}: некорректная группа {tag!r}')
                    groups[tag] = []
                else:
                    value = line.split('#', 1)[0].strip()
                    if not value:
                        continue
                    if tag is None:
                        raise ValueError(f'{manual_path.name}, строка {line_number}: перед подсетями нужен заголовок #### ruleTag')
                    try:
                        groups[tag].append(str(ipaddress.ip_network(value, strict=True)))
                    except ValueError as error:
                        raise ValueError(f'{manual_path.name}, строка {line_number}: некорректная подсеть {value!r}') from error
            manual = {'rules': [{'ruleTag': tag, 'ip': values} for tag, values in sorted(groups.items())]}
    if manual_ips is not None and manual_ips.is_file():
        prefixes = []
        for line_number, line in enumerate(manual_ips.read_text().splitlines(), 1):
            value = line.split('#', 1)[0].strip()
            if not value:
                continue
            try:
                prefixes.append(str(ipaddress.ip_network(value, strict=True)))
            except ValueError as error:
                raise ValueError(f'ip.txt, строка {line_number}: некорректная подсеть {value!r}') from error
        if any(rule['ruleTag'] == 'legacy' for rule in manual['rules']):
            raise ValueError('Группа legacy задаётся только в ip.txt, удалите её из config/manual.txt')
        raw_manual_ips = prefixes
        manual['rules'].append({'ruleTag': 'legacy', 'ip': prefixes, 'respect_exclusions': True})
    manual['rules'].sort(key=lambda rule: rule['ruleTag'])
    policies = {rule['ruleTag']: rule.get('respect_exclusions', False) for rule in manual['rules']}
    if any(type(value) is not bool for value in policies.values()):
        raise ValueError('manual.json: respect_exclusions должен быть true или false')
    manual = compact_rules(manual, [rule['ruleTag'] for rule in manual['rules']], dual_stack=True)
    if exclusion:
        restricted = exclusion.filter_ip_rules({'rules': [
            rule for rule in manual['rules'] if policies[rule['ruleTag']]
        ]})['rules']
        manual['rules'] = sorted(restricted + [
            rule for rule in manual['rules'] if not policies[rule['ruleTag']]
        ], key=lambda rule: rule['ruleTag'])
    ipv4_index = exclusion.ipv4_index() if exclusion else None
    manifest = {
        'version': 1,
        'inputs': routing_fingerprint({
            **outputs, 'scanner': args.scanner,
            **({'sites': args.sites, 'asn_file': args.asn_file or args.sites.with_name('asn.txt')}
               if hasattr(args, 'sites') else {}),
        }),
        'sites': [list(entry) for entry in entries],
        'asns': sorted(explicit),
    }
    if manual_path is not None:
        manifest['inputs']['manual_rules'] = routing_fingerprint({'manual': manual_path})['manual']
    if manual_ips is not None:
        manifest['inputs']['manual_ips'] = routing_fingerprint({'manual': manual_ips})['manual']
    if limits is not None:
        manifest['prefix_limits'] = limits.signature()
        manifest['inputs']['prefix_limits'] = routing_fingerprint({'policy': args.prefix_limits})['policy']
        manifest['inputs']['dns_provenance'] = routing_fingerprint({'provenance': previous_provenance})['provenance']
    if full_refresh:
        manifest['full_refresh'] = True
    if ipv4_index is not None:
        manifest['ipv4_exclusions'] = sha256(json.dumps(ipv4_index, sort_keys=True).encode()).hexdigest()
    if exclusion is not None:
        policy = [sorted(exclusion.asns), [str(network) for family in (4, 6)
                                          for network in exclusion.ranges[family]]]
        manifest['exclusion_policy'] = sha256(json.dumps(policy).encode()).hexdigest()
    implementation = routing_fingerprint({
        'generator': Path(__file__), 'asn_routes': Path(__file__).with_name('asn_routes.py'),
        'exclusion_policy': Path(__file__).with_name('exclusion_policy.py'),
        'prefix_limits': Path(__file__).with_name('prefix_limits.py'),
    })
    saved = None
    if resume:
        if not (resume / 'checkpoint.json').is_file():
            raise RuntimeError('В артефакте нет checkpoint.json. Этот запуск нельзя продолжить автоматически.')
        saved = json.loads((resume / 'checkpoint.json').read_text())
        changed = [name for name, digest in manifest['inputs'].items()
                   if name not in ('sites', 'asn_file') and saved.get('inputs', {}).get(name) != digest]
        if (saved.get('version') != manifest['version'] or changed
                or saved.get('full_refresh', False) != full_refresh):
            detail = ', '.join(changed) or 'версия формата'
            raise RuntimeError(f'Контрольная точка несовместима. Изменились: {detail}.')
    if args.evidence:
        write_json(args.evidence / 'checkpoint.json', manifest)
    if resume and saved == manifest and (resume / 'prepared.json').is_file():
        prepared = json.loads((resume / 'prepared.json').read_text())
        files = [*outputs, 'scan-summary.md', 'completeness.json']
        evidence_files = prepared_evidence(resume)
        saved_files = {name: resume / name for name in files} | evidence_files
        if prepared.get('implementation') == implementation:
            if prepared.get('files') != routing_fingerprint(saved_files) or not all(p.is_file() for p in saved_files.values()):
                raise RuntimeError('Контрольная точка публикации повреждена: файлы не совпадают с контрольными суммами.')
            status = json.loads(saved_files['completeness.json'].read_text())
            if not any(status.get(key) for key in ('domains_without_complete_dns_bgp',
                                                    'asns_without_prefixes', 'asn_export_error')):
                for name, path in outputs.items():
                    path.parent.mkdir(parents=True, exist_ok=True)
                    copyfile(saved_files[name], path)
                for name in ('scan-summary.md', 'completeness.json', *evidence_files):
                    copyfile(saved_files[name], args.evidence / name)
                save_prepared(args.evidence, outputs, implementation)
                print('Восстановлены готовые файлы маршрутизации. Продолжаем с публикации.', flush=True)
                return
    previous_domains = json.loads(args.domains_output.read_text()) if args.domains_output.exists() else {'rules': []}
    if args.output.exists() and not args.sources_output.exists():
        raise RuntimeError('Инкрементальный сбор требует sources.json для сохранения групп подсетей.')
    previous_sources = json.loads(args.sources_output.read_text()) if args.sources_output.exists() else {'rules': []}
    previous_tags = [r['ruleTag'] for r in previous_domains['rules']]
    previous_domains = domain_rules(previous_domains, previous_tags, include_seed=False)
    domain_groups = {r['ruleTag']: set(r['domain']) for r in previous_domains['rules']}
    source_groups = {r['ruleTag']: set(r['ip']) for r in previous_sources['rules']}
    for rule in previous_sources.get('manual_rules', []):
        source_groups.get(rule['ruleTag'], set()).difference_update(rule['ip'])
    known = {matcher.split(':', 1)[1] for group in domain_groups.values() for matcher in group}
    retry_names = set(previous_sources.get('pending_dns', []))
    excluded_asns = exclusion.asns if exclusion else set()
    previous_excluded = set(previous_sources.get('excluded_domains', [])) if (
        exclusion and set(previous_sources.get('excluded_asns', [])) == excluded_asns
    ) else set()
    discovery = {'domains': [], 'pages': [], 'complete': True}
    browser_entries = entries
    flags = ['-v'] if args.verbose else []
    if resume and (resume / 'discovery.json').is_file():
        old_discovery = json.loads((resume / 'discovery.json').read_text())
        saved_sites = dict(saved['sites'])
        current_sites = dict(entries)
        discovery['pages'] = [page for page in old_discovery['pages']
                              if page['site'] in current_sites and saved_sites.get(page['site']) == current_sites[page['site']]]
        restored = {page['site'] for page in discovery['pages']}
        browser_entries = [(host, url) for host, url in entries if host not in restored]
        print(f'Chromium: восстановлено страниц {len(restored)}, новых запросов {len(browser_entries)}.', flush=True)
    if browser_entries:
        # Reuse the production curl/Chromium phase without executing its DNS phase.
        # Fail closed if SubnetResolve changes its phase boundary.
        marker = "\nunset inputs\nstage_name='Этап 3/4: DNS'\n"
        scanner = args.scanner.read_text()
        if scanner.count(marker) != 1:
            raise RuntimeError('Не найдена граница этапов Chromium и DNS в SubnetResolve.sh.')
        browser_phase = scanner.split(marker, 1)[0] + '\nfinish_progress\ncat "$batch/discovery.json"\n'
        try:
            browser = subprocess.run(['bash', '-c', browser_phase, str(args.scanner), '-parse', '-s',
                                      *flags, '--', *[url for _, url in browser_entries]],
                                     stdout=subprocess.PIPE, text=True,
                                     timeout=max(0.1, min(6600, deadline - time.monotonic())), check=True)
            discovery['pages'].extend(json.loads(browser.stdout)['pages'])
        except (subprocess.SubprocessError, ValueError) as error:
            print(f'Chromium: сбор страниц не завершён ({error.__class__.__name__}). Исходные домены сохранены.', file=sys.stderr)
            discovery['complete'] = False
    discovery['complete'] = discovery['complete'] and all(not page['errors'] for page in discovery['pages'])
    discovery['domains'] = sorted({host for host, _ in entries} |
                                  {host for page in discovery['pages'] for host in page['domains']})
    tags = {host for host, _ in entries}
    candidates = {
        host: {host} | {name for matcher in domain_groups.get(host, ())
                        if not full_refresh and (name := matcher.split(':', 1)[1]) in retry_names}
        for host in tags
    }
    for page in discovery['pages']:
        candidates[page['site']].update(page['domains'])
        for error in page['errors']:
            message = error.removesuffix('; домен будет проверен через DNS/BGP')
            print(f"[{page['site']}] {message}", file=sys.stderr)
    discovered = set().union(*candidates.values())
    pending = sorted(discovered | known) if full_refresh else sorted(
        host for host in discovered if host in retry_names or host not in known | previous_excluded
    )
    skipped_existing = len(discovered - set(pending))
    print(f'DNS Check-Host: на проверку {len(pending)}, пропущено известных {skipped_existing}.', flush=True)
    observations = []
    responses = {}
    if args.evidence:
        args.evidence.mkdir(parents=True, exist_ok=True)
        write_json(args.evidence / 'discovery.json', discovery)
    if resume and (resume / 'dns-checkpoint.json').is_file() and (
            saved.get('ipv4_exclusions') == manifest.get('ipv4_exclusions')):
        saved_dns = json.loads((resume / 'dns-checkpoint.json').read_text())
        if any(
            row['domain'] != host or row['complete'] is not True or not (row['results'] or row.get('excluded_ips'))
            for host, row in saved_dns.items()
        ):
            raise ValueError('DNS/BGP: контрольная точка содержит неполные или незапрошенные домены.')
        responses.update({host: row for host, row in saved_dns.items() if host in pending})
        print(f'DNS/BGP: восстановлено доменов {len(responses)}.', flush=True)
    remaining = [host for host in pending if host not in responses]
    if args.evidence:
        write_json(args.evidence / 'dns-checkpoint.json', responses)
    for start in range(0, len(remaining), 32):
        batch = remaining[start:start + 32]
        budget = deadline - time.monotonic()
        if budget <= 0:
            print('Истёк общий лимит DNS/BGP. Сохраняем завершённые пакеты.', file=sys.stderr)
            break
        try:
            with ExitStack() as stack:
                env = os.environ.copy()
                if ipv4_index is not None:
                    index_file = stack.enter_context(tempfile.NamedTemporaryFile(mode='w', encoding='utf-8'))
                    json.dump(ipv4_index, index_file, separators=(',', ':'))
                    index_file.flush()
                    env['SUBNET_EXCLUDED_IPV4_INDEX'] = index_file.name
                scan = subprocess.run(['bash', str(args.scanner), '-s', *flags, '--', *batch],
                                      stdout=subprocess.PIPE, text=True, timeout=budget, env=env)
        except subprocess.TimeoutExpired:
            print('Истёк лимит DNS/BGP. Сохраняем найденные имена и полученные префиксы.', file=sys.stderr)
            break
        if args.evidence:
            (args.evidence / f'scanner-output-{start // 32 + 1}.json').write_text(scan.stdout)
        if scan.returncode not in (0, 3):
            print(f'DNS/BGP завершился с ошибкой {scan.returncode}. Сохраняем обнаруженные имена. См. журнал.', file=sys.stderr)
            break
        try:
            data = json.loads(scan.stdout)
        except json.JSONDecodeError:
            print('DNS/BGP вернул некорректный JSON. Сохраняем обнаруженные имена и готовые пакеты.',
                  file=sys.stderr)
            break
        rows = data['domains'] if 'domains' in data else [data]
        received = {row['domain']: row for row in rows}
        if len(received) != len(rows) or set(received) != set(batch):
            raise ValueError(f'DNS/BGP вернул другой список доменов. Нет: {sorted(set(batch)-received.keys())}. '
                             f'Лишние: {sorted(received.keys()-set(batch))}.')
        responses.update(received)
        if args.evidence:
            write_json(args.evidence / 'dns-checkpoint.json', {
                host: row for host, row in responses.items() if row['complete'] is True and (row['results'] or row.get('excluded_ips'))
            })
    explicit = set(explicit) - excluded_asns
    resolved = {}
    excluded_ips = set()
    eligible = {host: [route for route in row['results'] if route.get('asn') not in excluded_asns]
                for host, row in responses.items()}
    if table is not None:
        from asn_routes import broadest_routes
        try:
            selected = iter(broadest_routes([route for routes in eligible.values() for route in routes], table))
            eligible = {host: [next(selected) for _ in routes] for host, routes in eligible.items()}
        except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
            print(f'BGP.tools: не удалось сверить перекрывающиеся анонсы: {error}. '
                  'Сохраняем префиксы из WHOIS.', file=sys.stderr)
    for host, row in responses.items():
        routes = eligible[host]
        if routes:
            resolved[host] = {str(ipaddress.ip_network(route['prefix'])) for route in routes}
            observations.extend(routes)
        excluded_ips.update(row.get('excluded_ips', []))
    excluded_domains = set()
    if exclusion:
        excluded_domains = exclusion.excluded_domains(known | discovered, set() if full_refresh else previous_excluded, responses)
        print(f'Исключения ASN: исключено доменов — {len(excluded_domains & (known | discovered))}; '
              f'пропущено уникальных IPv4 перед WHOIS — {len(excluded_ips)}.', flush=True)
    unresolved = [host for host in pending if host not in responses or responses[host]['complete'] is not True]
    no_prefix = set(pending) - resolved.keys()
    excluded_without_prefix = no_prefix & excluded_domains
    incomplete_details = {}
    for host in unresolved:
        if host not in responses:
            incomplete_details[host] = {'reason': 'scan_not_completed'}
            continue
        row = responses[host]
        errors = [error for error in row.get('errors', []) if not error.get('check_host')]
        failed_ips = [ipaddress.ip_address(error['ip']) for error in errors if error.get('ip')]
        if failed_ips and len(failed_ips) == len(errors) and all(not ip.is_global for ip in failed_ips):
            reason = 'non_public_ipv4'
        elif failed_ips:
            reason = 'bgp_incomplete'
        elif errors:
            reason = 'check_host_api_error'
        else:
            reason = 'no_ipv4_from_check_host'
        incomplete_details[host] = {'reason': reason, 'errors': errors}
    if unresolved:
        print('DNS/BGP без полного результата. Домены остаются на повтор: ' + ', '.join(unresolved), file=sys.stderr)
    if args.evidence:
        write_json(args.evidence / 'bgp-observations.json', observations)
    asn_error = None
    try:
        as_rules, as_missing, report = collect(explicit, observations)
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        asn_error = str(error)
        as_rules, as_missing = [], sorted(explicit)
        print(f'Выгрузка ASN недоступна: {error}. Сохраняем прежние ASN и результаты по доменам.', file=sys.stderr)
        report = '## Покрытие ASN\n\nВыгрузка BGP.tools недоступна. См. журнал запуска.\n'
    print(report, flush=True)
    complete = discovery['complete'] and not unresolved and not as_missing and not invalid and asn_error is None
    if full_refresh:
        # Old names are queried to backfill evidence, even if no current site
        # requests them. Only the active discoveries can veto replacement.
        complete = (discovery['complete'] and not (discovered & set(unresolved))
                    and not as_missing and not invalid and asn_error is None)
        if complete:
            source_groups = {tag: prefixes for tag, prefixes in source_groups.items() if tag == 'legacy'}
            domain_groups = {tag: matchers for tag, matchers in domain_groups.items() if tag == 'legacy'}
            known = set()
            retry_names = set()
            unresolved = sorted(discovered & set(unresolved))
        else:
            excluded_domains |= previous_excluded
    for rule in as_rules:
        if rule['ip']:
            source_groups.setdefault(rule['ruleTag'], set()).update(rule['ip'])
    for tag, hosts in candidates.items():
        new_matchers = {'domain:' + host for host in hosts - known - excluded_domains}
        if new_matchers:
            domain_groups.setdefault(tag, set()).update(new_matchers)
        for host in sorted(hosts & resolved.keys()):
            source_groups.setdefault(tag, set()).update(resolved[host])
    sources = {'rules': [{'ruleTag': tag, 'ip': sorted(values)} for tag, values in sorted(source_groups.items())]}
    domains = {'rules': [{'ruleTag': tag, 'domain': sorted(values)} for tag, values in sorted(domain_groups.items())]}
    domains = domain_rules(domains, domain_groups, include_seed=False)
    if exclusion:
        sources = exclusion.filter_ip_rules(sources)
        domains = exclusion.filter_domain_rules(domains, excluded_domains)
    sources = apply_manual_rules(sources, manual)
    if limits is not None:
        from prefix_limits import merge_observations
        previous = json.loads(previous_provenance.read_bytes()) if previous_provenance.is_file() else {}
        provenance = merge_observations(previous, responses)
        manual_metadata = limits.filter_rules({'rules': sources.get('manual_rules', [])}, domains, provenance)['rules']
        sources = limits.filter_rules(sources, domains, provenance)
        sources['manual_rules'] = manual_metadata
    sources = redistribute_legacy(sources)
    metadata = sources.get('manual_rules')
    sources = compact_rules(sources, [rule['ruleTag'] for rule in sources['rules']], dual_stack=True)
    if metadata:
        legacy = next((rule['ip'] for rule in sources['rules'] if rule['ruleTag'] == 'legacy'), [])
        sources['manual_rules'] = [({**rule, 'ip': legacy} if rule['ruleTag'] == 'legacy' else rule)
                                   for rule in metadata if rule['ruleTag'] != 'legacy' or legacy]
    sources['pending_dns'] = sorted((retry_names - set(pending)) | set(unresolved))
    if exclusion:
        sources['excluded_asns'] = sorted(excluded_asns)
        sources['excluded_domains'] = sorted(excluded_domains)
    if limits is not None:
        sources['ipv4_prefix_limits'] = limits.signature()
        if limits.unobserved:
            print(f'Ограничение ASN: широких записей без сохранённых DNS-IP — {len(limits.unobserved)}; '
                  'они не включены в direct. См. prefix_limits_without_dns в полноте сбора.', file=sys.stderr)
    result = global_rules(sources)
    if args.evidence:
        (args.evidence / 'scan-summary.md').write_text(report)
        write_json(args.evidence / 'completeness.json', {
            'complete': complete, 'mode': 'full-refresh' if full_refresh else 'incremental', 'invalid_sites': invalid, 'dns_requested': len(pending),
            'dns_skipped_existing': skipped_existing,
            'domains_without_complete_dns_bgp': unresolved,
            'domains_without_any_prefix': sorted(no_prefix - excluded_without_prefix),
            'domains_excluded_by_asn_without_prefix': sorted(excluded_without_prefix),
            'incomplete_dns_bgp_details': {host: incomplete_details[host] for host in unresolved},
            'excluded_ipv4_skipped_before_whois': len(excluded_ips),
            'prefix_limits_without_dns': limits.unobserved if limits else [],
            'excluded_domains': sorted(excluded_domains & (known | discovered)),
            'asns_without_prefixes': as_missing,
            'asn_export_error': asn_error,
            'services_written': len(result['rules']),
            'prefixes_written': sum(len(rule['ip']) for rule in result['rules']),
        })
    if not complete and not args.allow_partial:
        raise RuntimeError('Инкрементальный сбор неполный. Подробности в журнале.')
    write_json(args.output, result)
    write_json(args.domains_output, domains)
    write_json(args.sources_output, sources)
    if manual_ips is not None:
        if limits is not None:
            narrowed = limits.filter_rules({'rules': [{'ruleTag': 'legacy', 'ip': raw_manual_ips}]}, domains, provenance)
            raw_manual_ips = [value for rule in narrowed['rules'] for value in rule['ip']]
        remaining = redistribute_legacy({'rules': [
            *[rule for rule in sources['rules'] if rule['ruleTag'] != 'legacy'],
            {'ruleTag': 'legacy', 'ip': raw_manual_ips},
        ]})
        legacy = next((rule['ip'] for rule in remaining['rules'] if rule['ruleTag'] == 'legacy'), [])
        manual_ips.parent.mkdir(parents=True, exist_ok=True)
        temporary = manual_ips.with_name(manual_ips.name + '.tmp')
        temporary.write_text(format_manual_ips(legacy))
        temporary.replace(manual_ips)

    if args.evidence:
        save_prepared(args.evidence, outputs, implementation)


def prepared_evidence(directory):
    paths = [directory / 'discovery.json', directory / 'dns-checkpoint.json',
             *sorted(directory.glob('scanner-output-*.json'))]
    return {path.name: path for path in paths if path.is_file()}


def save_prepared(evidence, outputs, implementation):
    files = {name: evidence / name for name in (*outputs, 'scan-summary.md', 'completeness.json')}
    for name, source in outputs.items():
        copyfile(source, files[name])
    write_json(evidence / 'prepared.json', {
        'files': routing_fingerprint(files | prepared_evidence(evidence)), 'implementation': implementation,
    })


def main():
    from asn_routes import BgpTable, asn, collect
    parser = argparse.ArgumentParser(description=__doc__)
    root = Path(__file__).resolve().parent.parent
    parser.add_argument('--sites', type=Path, default=root / 'sites.txt')
    parser.add_argument('--asn-file', type=Path)
    parser.add_argument('--output', type=Path, default=root / 'generated/IP.json')
    parser.add_argument('--sources-output', type=Path, help='Original per-service prefixes before global grouping')
    parser.add_argument('--domains-output', type=Path, help='Defaults to domains.json beside IP.json')
    parser.add_argument('--resume', type=Path, help='Resume incremental routing from an evidence directory')
    parser.add_argument('--exclude-asns', '--exclude-cloudflare', action='store_true',
                        help='Exclude ASNs listed in source/routing/exclude.txt from direct rules')
    parser.add_argument('--incremental', action='store_true', help='Resolve only names absent from published domain rules')
    parser.add_argument('--full-refresh', action='store_true', help='Rescan all domains and replace generated rules after a complete scan')
    parser.add_argument('--allow-partial', action='store_true', help='Keep available prefixes and union previous entries on incomplete scans')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show detailed scanner stages on stderr')
    parser.add_argument('--evidence', type=Path, help='Directory for raw scan output and completeness report')
    parser.add_argument('--scanner', type=Path, default=root.parent / 'SubnetResolve.sh')
    args = parser.parse_args()
    if args.full_refresh and not args.incremental:
        parser.error('--full-refresh requires --incremental')
    if args.resume and (not args.incremental or not args.evidence):
        parser.error('--resume requires --incremental and --evidence')
    args.manual_rules = args.sites.parent / 'config/manual.txt'
    args.manual_ips = args.sites.with_name('ip.txt')
    args.prefix_limits = args.sites.parent / 'config/prefix-limits.txt'
    args.previous_provenance = args.sites.parent / 'state/dns-provenance.json'
    entries = services(args.sites, asn)
    explicit = {tag for tag, _ in entries if asn(tag)}
    entries = [(tag, value) for tag, value in entries if not asn(tag)]
    asn_file = args.asn_file or args.sites.with_name('asn.txt')
    if asn_file.exists() or args.asn_file:
        for tag, value in services(asn_file, asn):
            origin = asn(tag)
            if not origin and tag == 'bgp.he.net':
                origin = asn(urlsplit(value).path.strip('/'))
            if not origin:
                raise ValueError(f'Invalid ASN entry: {value}')
            explicit.add(origin)
    if not entries and not explicit:
        raise ValueError('No domains or ASNs configured')
    if args.sources_output is None:
        args.sources_output = (root / 'state/sources.json' if args.output == root / 'generated/IP.json'
                               else args.output.with_name('sources.json'))
    if args.domains_output is None:
        args.domains_output = args.output.with_name('domains.json')
    if args.exclude_asns and not args.incremental:
        parser.error('--exclude-asns requires --incremental')
    if args.incremental:
        policy = None
        table = BgpTable()
        args.prefix_limit_policy = None
        if args.prefix_limits.is_file():
            from prefix_limits import PrefixLimits
            try:
                args.prefix_limit_policy = PrefixLimits.load(args.prefix_limits, table)
            except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
                parser.exit(1, f'Ограничения подсетей: не удалось загрузить конфигурацию или BGP-снимок. {error}\n')
        if args.exclude_asns:
            from exclusion_policy import ExclusionPolicy
            try:
                policy = ExclusionPolicy.load(table=table)
            except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
                parser.exit(1, f'Исключения ASN: не удалось загрузить ASN и префиксы. '
                               f'Сбор и публикация не запущены. {error}\n')
        incremental_update(args, entries, explicit,
                           lambda explicit, observed: collect(explicit, observed, table=table), policy, table=table)
        return
    with tempfile.TemporaryDirectory(prefix='routing-bgp-') as directory:
        metadata = Path(directory) / 'observations.json'
        scan = subprocess.run(
            ['bash', str(args.scanner), '-parse', '-rules', '-s',
             *(['-v'] if args.verbose else []), '--', *[value for _, value in entries]],
            stdout=subprocess.PIPE, text=True, timeout=6600,
            env={**os.environ, 'SUBNET_BGP_OBSERVATIONS': str(metadata)}
        ) if entries else subprocess.CompletedProcess([], 0, '{"rules":[]}')
        observations = json.loads(metadata.read_text()) if metadata.exists() else []
    if args.evidence:
        args.evidence.mkdir(parents=True, exist_ok=True)
        (args.evidence / 'scanner-output.json').write_text(scan.stdout)
        write_json(args.evidence / 'bgp-observations.json', observations)
    if scan.returncode not in (0, 3):
        raise RuntimeError('Domain scan failed; existing routing files retained.')
    data = json.loads(scan.stdout)
    domain_tags = [host for host, _ in entries]
    domains = domain_rules(data, domain_tags)
    as_rules, as_missing, report = collect(explicit, observations)
    print(report, flush=True)
    if args.evidence:
        (args.evidence / 'scan-summary.md').write_text(report)
    partial = scan.returncode == 3 or bool(as_missing)
    if partial and not args.allow_partial:
        raise RuntimeError('Scan incomplete or failed; existing routing files retained.')
    expected = domain_tags + sorted(explicit)
    data['rules'] = sorted(data['rules'] + as_rules, key=lambda r: r['ruleTag'])
    result = compact_rules(data, expected, dual_stack=True)
    missing = [r['ruleTag'] for r in result['rules'] if not r['ip']]
    previous_path = args.sources_output if args.sources_output.exists() else args.output
    if partial and previous_path.exists():
        previous = json.loads(previous_path.read_text())
        old = {r['ruleTag']: r['ip'] for r in previous['rules']}
        for rule in result['rules']:
            rule['ip'] += old.get(rule['ruleTag'], [])
        result = compact_rules(result, expected, dual_stack=True)
    result['rules'] = [r for r in result['rules'] if r['ip']]
    if not result['rules']:
        raise RuntimeError('No usable prefixes; existing IP.json/domains.json retained.')
    if previous_path.exists():
        old_rules = json.loads(previous_path.read_text())['rules']
        for rule in old_rules:
            if rule['ruleTag'] == 'legacy':
                networks = [ipaddress.ip_network(value, strict=True) for value in rule['ip']]
                result['rules'].append({'ruleTag':'legacy', 'ip':[str(n) for version in (4,6) for n in ipaddress.collapse_addresses(n for n in networks if n.version==version)]})
    if scan.returncode == 3 and args.domains_output.exists():
        previous_domains = json.loads(args.domains_output.read_text())
        old = {r['ruleTag']:r['domain'] for r in previous_domains['rules']}
        for rule in domains['rules']:
            rule['domain'] = sorted(set(rule['domain'] + old.get(rule['ruleTag'], [])))
        domains = domain_rules(domains, [host for host, _ in entries])
    sources = {'rules':sorted(result['rules'], key=lambda r:r['ruleTag'])}
    result = global_rules(sources)
    if args.evidence:
        (args.evidence / 'completeness.json').write_text(json.dumps({
            'complete': not partial, 'services_without_new_prefixes': missing,
            'services_written': len(result['rules']),
            'prefixes_written': sum(len(r['ip']) for r in result['rules'])}, indent=2) + '\n')
    if partial:
        print('WARNING: неполный сбор; сохранены доступные и прежние подсети. Подробности в артефактах запуска.', file=sys.stderr)

    write_json(args.output, result)
    write_json(args.domains_output, domains)
    write_json(args.sources_output, sources)


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', dir=path.parent, delete=False) as stream:
            temporary = stream.name
            json.dump(data, stream, ensure_ascii=False, indent=2)
            stream.write('\n')
        os.replace(temporary, path)
    finally:
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)


if __name__ == '__main__':
    main()
