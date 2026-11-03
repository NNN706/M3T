"""Publish routing output on the latest test branch without overwriting newer inputs."""
import argparse
from pathlib import Path
import shutil
import subprocess
import tempfile

INPUTS = ['source/routing/sites.txt', 'source/routing/ASN.txt', 'source/routing/asn_routes.py', 'source/SubnetResolve.sh',
          'source/routing/update_routing.py', 'source/routing/domains.json', 'source/routing/sources.json', 'source/routing/IP.json']
OUTPUT = 'source/routing/IP.json'

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
    for attempt in range(3):
        git(repo, 'fetch', 'origin', 'refs/heads/test')
        head = git(repo, 'rev-parse', 'FETCH_HEAD').stdout.strip()
        if git(repo, 'diff', '--quiet', base, head, '--', *INPUTS, check=False).returncode:
            raise RuntimeError('Routing inputs or previous IP.json changed during scan; result retained in artifacts. Run update again.')
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
                    print('IP.json unchanged; no commit needed.')
                    return
                git(worktree, '-c', 'user.name=github-actions[bot]',
                    '-c', 'user.email=41898282+github-actions[bot]@users.noreply.github.com',
                    'commit', '-m', 'Update service routing prefixes')
                pushed = git(worktree, 'push', 'origin', 'HEAD:refs/heads/test', check=False)
                if pushed.returncode == 0:
                    print('Published source/routing/IP.json to test.')
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
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--sources', type=Path)
    parser.add_argument('--domains', type=Path)
    parser.add_argument('--base', required=True)
    args = parser.parse_args()
    publish(args.repo.resolve(), args.output.resolve(), args.base, domains=args.domains.resolve() if args.domains else None, sources=args.sources.resolve() if args.sources else None)

if __name__ == '__main__':
    main()
