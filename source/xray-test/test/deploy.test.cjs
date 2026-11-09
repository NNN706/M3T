const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {spawnSync} = require('node:child_process');

test('invalid Xray config stops before starting a local container', () => {
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
  try {
    const result = spawnSync('bash', ['deploy.sh'], {encoding: 'utf8', timeout: 15000, env: {
      ...process.env, PATH: tmp + ':' + process.env.PATH,
      DOCKER_TEST_COMMANDS: commandsFile,
      XRAY_IMAGE: 'ghcr.io/xtls/xray-core:26.10.31@sha256:' + 'a'.repeat(64),
      XRAY_EVIDENCE: path.join(tmp, 'evidence'),
    }});
    assert.equal(result.status, 1, result.stderr);
    assert.match(result.stderr, /Invalid Xray config fixture/);
    const commands = fs.readFileSync(commandsFile, 'utf8').trim().split('\n');
    assert.equal(commands.length, 3);
    assert.match(commands[2], /^run --rm --network none .* run -test -config /);
  } finally {
    fs.rmSync(tmp, {recursive: true, force: true});
  }
});
