const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {spawnSync} = require('node:child_process');

for (const useSudo of [false, true]) {
  test('invalid Xray config stops before starting a local container, sudo=' + useSudo, () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'xray-deploy-'));
    const commandsFile = path.join(tmp, 'docker-commands');
    fs.writeFileSync(path.join(tmp, 'docker'), `#!/usr/bin/env bash
printf '%s\\n' "$*" >> "$DOCKER_TEST_COMMANDS"
case "$1" in
    info|pull) exit 0 ;;
    run) echo 'Invalid Xray config fixture' >&2; exit 1 ;;
    *) exit 99 ;;
esac
`, {mode: 0o755});
    fs.writeFileSync(path.join(tmp, 'sudo'), `#!/usr/bin/env bash
[[ "$1" == -n && "$2" == docker ]] || exit 98
printf 'sudo\\n' >> "$DOCKER_TEST_COMMANDS"
shift
exec "$@"
`, {mode: 0o755});
    try {
      const result = spawnSync('bash', ['deploy.sh'], {encoding: 'utf8', timeout: 15000, env: {
        ...process.env, PATH: tmp + ':' + process.env.PATH,
        DOCKER_TEST_COMMANDS: commandsFile,
        XRAY_IMAGE: 'ghcr.io/xtls/xray-core:26.10.31@sha256:' + 'a'.repeat(64),
        XRAY_DOCKER_SUDO: useSudo ? '1' : '0',
        XRAY_EVIDENCE: path.join(tmp, 'evidence'),
      }});
      assert.equal(result.status, 1, result.stderr);
      assert.match(result.stderr, /Invalid Xray config fixture/);
      const calls = fs.readFileSync(commandsFile, 'utf8').trim().split('\n');
      assert.equal(calls.filter(command => command === 'sudo').length, useSudo ? 3 : 0);
      const commands = calls.filter(command => command !== 'sudo');
      assert.equal(commands.length, 3);
      assert.match(commands[2], /^run --rm --network none .* run -test -config /);
    } finally {
      fs.rmSync(tmp, {recursive: true, force: true});
    }
  });
}

test('negative probe requires the default block access log for the exact IP', () => {
  const script = fs.readFileSync('deploy.sh', 'utf8');
  const start = `python3 - "$evidence/preflight-xray.log" "$negative" <<'PY'`;
  const probe = script.split(start + '\n')[1].split('\nPY\n')[0];
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'xray-preflight-'));
  try {
    const log = path.join(tmp, 'access.log');
    for (const [line, status] of [
      ['accepted tcp:1.1.1.1:443 [routing-test-socks >> block]', 0],
      ['accepted tcp:1.1.1.1:443 [routing-test-socks -> block]', 1],
      ['accepted tcp:1.1.1.1:443 [routing-test-socks >> direct]', 1],
      ['accepted tcp:11.1.1.1:443 [routing-test-socks >> block]', 1],
    ]) {
      fs.writeFileSync(log, line);
      const result = spawnSync('python3', ['-c', probe, log, '1.1.1.1'], {encoding: 'utf8'});
      assert.equal(result.status, status, result.stderr);
    }
  } finally {
    fs.rmSync(tmp, {recursive: true, force: true});
  }
});
