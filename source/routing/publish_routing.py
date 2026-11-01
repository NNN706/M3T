"""Publish routing output on the latest test branch without overwriting newer inputs."""
import argparse
from pathlib import Path
import shutil
import subprocess
import tempfile

INPUTS = ['source/routing/sites.txt', 'source/SubnetResolve.sh',
          'source/routing/update_routing.py', 'source/routing/IP.txt']
OUTPUT = 'source/routing/IP.txt'

def git(repo, *args, check=True):
    return subprocess.run(['git', '-C', str(repo), *args], text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=check)

def publish(repo, output, base, branch='test'):
    if branch != 'test':
        raise ValueError('Only test publication is enabled')
    payload = output.read_bytes()
    for attempt in range(3):
        git(repo, 'fetch', 'origin', 'refs/heads/test')
        head = git(repo, 'rev-parse', 'FETCH_HEAD').stdout.strip()
        if git(repo, 'diff', '--quiet', base, head, '--', *INPUTS, check=False).returncode:
            raise RuntimeError('Routing inputs or previous IP.txt changed during scan; result retained in artifacts. Run update again.')
        with tempfile.TemporaryDirectory(prefix='routing-publish-') as directory:
            worktree = Path(directory) / 'checkout'
            git(repo, 'worktree', 'add', '--detach', str(worktree), head)
            try:
                target = worktree / OUTPUT
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(payload)
                git(worktree, 'add', '--', OUTPUT)
                if git(worktree, 'diff', '--cached', '--quiet', check=False).returncode == 0:
                    print('IP.txt unchanged; no commit needed.')
                    return
                git(worktree, '-c', 'user.name=github-actions[bot]',
                    '-c', 'user.email=41898282+github-actions[bot]@users.noreply.github.com',
                    'commit', '-m', 'Update service routing prefixes')
                pushed = git(worktree, 'push', 'origin', 'HEAD:refs/heads/test', check=False)
                if pushed.returncode == 0:
                    print('Published source/routing/IP.txt to test.')
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
    parser.add_argument('--base', required=True)
    args = parser.parse_args()
    publish(args.repo.resolve(), args.output.resolve(), args.base)

if __name__ == '__main__':
    main()
