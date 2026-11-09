"""Publish routing output on the latest test branch without overwriting newer inputs."""
import argparse
from pathlib import Path
import shutil
import subprocess
import tempfile

LISTS = ['source/routing/sites.txt', 'source/routing/ASN.txt']
INPUTS = ['source/routing/cloudflare.py', 'source/routing/asn_routes.py', 'source/SubnetResolve.sh',
          'source/routing/update_routing.py', 'source/routing/domains.json', 'source/routing/sources.json', 'source/routing/IP.json']
OUTPUT = 'source/routing/IP.json'
REPORT = 'source/routing/asn-report.md'
REPORT_INPUTS = [OUTPUT, REPORT, 'source/routing/routing_report.py', 'source/routing/asn_routes.py']

def git(repo, *args, check=True):
    return subprocess.run(['git', '-C', str(repo), *args], text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=check)

def publish(repo, output, base, branch='test', domains=None, sources=None):
    if branch != 'test':
        raise ValueError('Only test publication is enabled')
    payloads = {OUTPUT:output.read_bytes()}
    if domains is not None:
        payloads['source/routing/domains.json'] = domains.read_bytes()
    if sources is not None:
        payloads['source/routing/sources.json'] = sources.read_bytes()
    publish_payloads(repo, base, payloads, INPUTS, 'Update service routing prefixes')


def publish_payloads(repo, base, payloads, inputs, message):
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
                git(worktree, 'add', '--', *payloads)
                if git(worktree, 'diff', '--cached', '--quiet', check=False).returncode == 0:
                    print('Files unchanged; no commit needed: ' + ', '.join(payloads))
                    return
                git(worktree, '-c', 'user.name=github-actions[bot]',
                    '-c', 'user.email=41898282+github-actions[bot]@users.noreply.github.com',
                    'commit', '-m', message)
                pushed = git(worktree, 'push', 'origin', 'HEAD:refs/heads/test', check=False)
                if pushed.returncode == 0:
                    print('Published to test: ' + ', '.join(payloads))
                    return
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
    parser.add_argument('--sources', type=Path)
    parser.add_argument('--domains', type=Path)
    parser.add_argument('--base', required=True)
    args = parser.parse_args()
    if args.report:
        if args.sources or args.domains:
            parser.error('--sources and --domains require --output')
        publish_payloads(args.repo.resolve(), args.base, {REPORT: args.report.read_bytes()},
                         REPORT_INPUTS, 'Update overall routing ASN report')
    else:
        publish(args.repo.resolve(), args.output, args.base, domains=args.domains, sources=args.sources)

if __name__ == '__main__':
    main()
