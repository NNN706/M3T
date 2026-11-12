"""Publish routing output on the latest test branch without overwriting newer inputs."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

LISTS = ['source/routing/sites.txt', 'source/routing/asn.txt', 'source/routing/domains.txt']
INPUTS = ['source/routing/scripts/domain_coverage.cjs', 'source/routing/config/prefix-limits.txt', 'source/routing/scripts/prefix_limits.py', 'source/routing/state/dns-provenance.json', 'source/routing/scripts/build_routing.cjs', 'source/routing/config/manual.txt', 'source/routing/ip.txt', 'source/routing/scripts/exclusion_policy.py', 'source/routing/exclude.txt', 'source/routing/scripts/asn_routes.py', 'source/SubnetResolve.sh',
          'source/routing/scripts/update_routing.py', 'source/routing/generated/domains.json', 'source/routing/state/sources.json', 'source/routing/generated/IP.json']
OUTPUT = 'source/routing/generated/IP.json'
TEMPLATE = 'Templates/Routing-(RU-Direct)/routing-ru.json'
REPORT = 'source/routing/asn-report-full.md'
PROVENANCE = 'source/routing/state/dns-provenance.json'
REPORT_INPUTS = ['source/routing/scripts/domain_coverage.cjs', 'source/routing/config/prefix-limits.txt', 'source/routing/scripts/prefix_limits.py', 'source/routing/state/dns-provenance.json', OUTPUT, 'source/routing/state/sources.json', REPORT, PROVENANCE, 'source/routing/scripts/routing_report.py', 'source/routing/scripts/asn_routes.py']

def git(repo, *args, check=True):
    return subprocess.run(['git', '-C', str(repo), *args], text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=check)

def publish(repo, output, base, branch='test', domains=None, sources=None, *, build_routing=False, manual_ips=None):
    if branch != 'test':
        raise ValueError('Only test publication is enabled')
    payloads = {OUTPUT:output.read_bytes()}
    if domains is not None:
        payloads['source/routing/generated/domains.json'] = domains.read_bytes()
    if sources is not None:
        payloads['source/routing/state/sources.json'] = sources.read_bytes()
    if manual_ips is not None:
        payloads['source/routing/ip.txt'] = manual_ips.read_bytes()
    if build_routing and domains is None:
        raise ValueError('Сборка routing-ru.json требует domains.json')
    return publish_payloads(repo, base, payloads, INPUTS, 'Update service routing prefixes',
                            build_routing=build_routing)


def publish_payloads(repo, base, payloads, inputs, message, *, build_routing=False):
    for attempt in range(3):
        git(repo, 'fetch', 'origin', 'refs/heads/test')
        head = git(repo, 'rev-parse', 'FETCH_HEAD').stdout.strip()
        guarded = git(repo, 'diff', '--name-only', base, head, '--', *inputs).stdout.splitlines()
        if guarded:
            raise RuntimeError('Routing code or published JSON changed during scan: '
                               + ', '.join(guarded) + '. Results retained in artifacts.')
        changed_lists = git(repo, 'diff', '--name-only', base, head, '--', *LISTS).stdout.splitlines()
        if changed_lists:
            print('Publishing collected data without changing newer lists: ' + ', '.join(changed_lists))
        with tempfile.TemporaryDirectory(prefix='routing-publish-') as directory:
            worktree = Path(directory) / 'checkout'
            git(repo, 'worktree', 'add', '--detach', str(worktree), head)
            try:
                for path, payload in payloads.items():
                    target = worktree / path
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(payload)
                staged = list(payloads)
                if build_routing:
                    subprocess.run([
                        'node', str(Path(__file__).with_name('build_routing.cjs')), '--compact-domains',
                        str(worktree / TEMPLATE), str(worktree / 'source/routing/generated/domains.json'),
                        str(worktree / 'source/routing/state/sources.json')
                        if 'source/routing/state/sources.json' in payloads else '-',
                        str(worktree / 'source/routing/domains.txt')
                        if (worktree / 'source/routing/domains.txt').is_file() else '-',
                    ], check=True)
                    subprocess.run([
                        'node', str(Path(__file__).with_name('build_routing.cjs')),
                        str(worktree / TEMPLATE), str(worktree / OUTPUT),
                        str(worktree / 'source/routing/generated/domains.json'),
                    ], check=True)
                    staged.append(TEMPLATE)
                git(worktree, 'add', '--', *staged)
                if git(worktree, 'diff', '--cached', '--quiet', check=False).returncode == 0:
                    print('Files unchanged; no commit needed: ' + ', '.join(payloads))
                    return head
                git(worktree, '-c', 'user.name=github-actions[bot]',
                    '-c', 'user.email=41898282+github-actions[bot]@users.noreply.github.com',
                    'commit', '-m', message)
                pushed = git(worktree, 'push', 'origin', 'HEAD:refs/heads/test', check=False)
                if pushed.returncode == 0:
                    print('Published to test: ' + ', '.join(payloads))
                    return git(worktree, 'rev-parse', 'HEAD').stdout.strip()
                # Retry only when the remote branch advanced; authentication and policy errors remain failures.
                git(repo, 'fetch', 'origin', 'refs/heads/test')
                newest = git(repo, 'rev-parse', 'FETCH_HEAD').stdout.strip()
                if newest == head:
                    raise RuntimeError('GitHub rejected publication: ' + pushed.stderr.strip())
                print('test advanced during publication; retrying on its latest commit.')
            finally:
                git(repo, 'worktree', 'remove', '--force', str(worktree))
    raise RuntimeError('test kept changing during publication; output retained in artifacts.')

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, default=Path.cwd())
    operation = parser.add_mutually_exclusive_group(required=True)
    operation.add_argument('--output', type=Path)
    operation.add_argument('--report', type=Path)
    parser.add_argument('--provenance', type=Path)
    parser.add_argument('--sources', type=Path)
    parser.add_argument('--manual-ips', type=Path)
    parser.add_argument('--domains', type=Path)
    parser.add_argument('--base', required=True)
    parser.add_argument('--build-routing', action='store_true')
    args = parser.parse_args()
    if args.provenance and not args.report:
        parser.error('--provenance requires --report')
    if args.report:
        if args.build_routing:
            parser.error('--build-routing requires --output')
        if args.sources or args.domains or args.manual_ips:
            parser.error('--sources and --domains require --output')
        payloads = {REPORT: args.report.read_bytes()}
        if args.provenance:
            payloads[PROVENANCE] = args.provenance.read_bytes()
        published = publish_payloads(args.repo.resolve(), args.base, payloads,
                         REPORT_INPUTS, 'Update overall routing ASN report')
    else:
        published = publish(args.repo.resolve(), args.output, args.base, domains=args.domains,
                            sources=args.sources, build_routing=args.build_routing, manual_ips=args.manual_ips)
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as output:
            output.write(f'published_sha={published}\n')

if __name__ == '__main__':
    main()
