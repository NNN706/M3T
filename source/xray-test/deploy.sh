#!/usr/bin/env bash
set -euo pipefail
# Run only on the trusted self-hosted runner, with GitHub Environment secrets.
: "${XRAY_HOST:?Set XRAY_HOST}" "${XRAY_USER:?Set XRAY_USER}"
: "${XRAY_IMAGE:?Set ghcr.io/xtls/xray-core:VERSION@sha256:DIGEST}"
: "${XRAY_SSH_KEY:?Set SSH private key}" "${XRAY_KNOWN_HOSTS:?Set pinned known_hosts}"
XRAY_SSH_PORT=${XRAY_SSH_PORT:-22}
[[ $XRAY_HOST =~ ^[a-zA-Z0-9.-]+$ && $XRAY_USER =~ ^[a-zA-Z_][a-zA-Z0-9_-]*$ ]]
[[ $XRAY_SSH_PORT =~ ^[0-9]+$ ]]
[[ $XRAY_IMAGE =~ ^ghcr\.io/xtls/xray-core:[a-zA-Z0-9_.-]+@sha256:[a-f0-9]{64}$ ]]
[[ ${GITHUB_SHA:?} =~ ^[a-f0-9]{40}$ && ${GITHUB_RUN_ID:?} =~ ^[0-9]+$ ]]
root=$(cd "$(dirname "$0")/../.." && pwd)
evidence=${XRAY_EVIDENCE:-"${RUNNER_TEMP:?}/xray-evidence"}
mkdir -p "$evidence"
private=$(mktemp -d)
chmod 700 "$private"
printf '%s\n' "$XRAY_SSH_KEY" > "$private/key"
printf '%s\n' "$XRAY_KNOWN_HOSTS" > "$private/known_hosts"
chmod 600 "$private/key" "$private/known_hosts"
unset XRAY_SSH_KEY XRAY_KNOWN_HOSTS
opts=(-i "$private/key" -o BatchMode=yes -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$private/known_hosts" -o ConnectTimeout=15 -p "$XRAY_SSH_PORT")
remote="$XRAY_USER@$XRAY_HOST"
tunnel_pid=''
activated=0
cleanup() {
  status=$?
  if [[ $activated == 1 ]]; then
    ssh "${opts[@]}" "$remote" 'docker logs --timestamps m3t-xray-routing-test' > "$evidence/xray.log" 2>&1 || true
    ssh "${opts[@]}" "$remote" 'docker inspect --format "{{json .State}}" m3t-xray-routing-test' > "$evidence/container-state.json" 2>/dev/null || true
  fi
  [[ -z $tunnel_pid ]] || { kill "$tunnel_pid" 2>/dev/null || true; wait "$tunnel_pid" 2>/dev/null || true; }
  rm -rf "$private"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP
node "$root/source/xray-test/prepare.cjs" "$root/Templates/Routing-(RU-Direct)/routing-ru.json" "$evidence"
release="m3t-xray-routing-test/releases/$GITHUB_SHA-$GITHUB_RUN_ID"
ssh "${opts[@]}" "$remote" "mkdir -p '$release'"
ssh "${opts[@]}" "$remote" "cat > '$release/config.json'" < "$evidence/config.json"
# Validation precedes any change to the existing managed container.
ssh "${opts[@]}" "$remote" bash -s -- "$XRAY_IMAGE" "$release" "$GITHUB_SHA" <<'REMOTE'
set -euo pipefail
image=$1
release="$HOME/$2"
sha=$3
chmod 644 "$release/config.json"
docker pull "$image"
docker run --rm --network none -v "$release/config.json:/etc/xray/config.json:ro" "$image" run -test -config /etc/xray/config.json
if docker inspect m3t-xray-routing-test >/dev/null 2>&1; then
  [[ $(docker inspect --format '{{index .Config.Labels "com.docker.compose.project"}}' m3t-xray-routing-test) == m3t-xray-routing-test ]] || { echo 'Container name is owned by another project' >&2; exit 1; }
fi
cat > "$release/compose.json" <<JSON
{"services":{"xray":{"image":"$image","container_name":"m3t-xray-routing-test","restart":"unless-stopped","command":["run","-config","/etc/xray/config.json"],"ports":["127.0.0.1:10808:10808"],"volumes":["$release/config.json:/etc/xray/config.json:ro"],"labels":{"m3t.sha":"$sha"},"logging":{"driver":"json-file","options":{"max-size":"20m","max-file":"3"}}}}}
JSON
docker compose -p m3t-xray-routing-test -f "$release/compose.json" up -d
# No CPU quota or memory limit. Leave the candidate running after test failures.
sleep 2
[[ $(docker inspect --format '{{.State.Running}}' m3t-xray-routing-test) == true ]]
REMOTE
activated=1
# Ask SSH to allocate a free local forwarding port, avoiding collisions on the runner.
# A short-lived bound socket selects a port; ExitOnForwardFailure catches any race.
port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
ssh "${opts[@]}" -o ExitOnForwardFailure=yes -o ServerAliveInterval=15 -o ServerAliveCountMax=3 -N -L "127.0.0.1:$port:127.0.0.1:10808" "$remote" &
tunnel_pid=$!
for attempt in {1..30}; do
  kill -0 "$tunnel_pid" 2>/dev/null || { echo 'SSH tunnel stopped' >&2; exit 1; }
  if python3 -c 'import socket,sys; s=socket.create_connection(("127.0.0.1",int(sys.argv[1])),.2); s.close()' "$port" 2>/dev/null; then break; fi
  sleep 1
done
negative=$(cat "$evidence/negative-ip")
probe_started=$(ssh "${opts[@]}" "$remote" "date -u +%FT%TZ")
# Failed networking alone is not proof of block: require Xray's routing decision.
if curl -fsS --socks5-hostname "127.0.0.1:$port" --connect-timeout 5 --max-time 10 "https://$negative/" > /dev/null 2> "$evidence/negative-curl.log"; then
  echo 'Default block preflight unexpectedly succeeded' >&2; exit 1
fi
ssh "${opts[@]}" "$remote" "docker logs --since '$probe_started' m3t-xray-routing-test 2>&1" > "$evidence/preflight-xray.log"
python3 - "$evidence/preflight-xray.log" "$negative" <<'PY'
import sys
lines=open(sys.argv[1]).read().splitlines()
if not any(sys.argv[2]+':443' in line and 'routing-test-socks -> block' in line for line in lines):
    raise SystemExit('Не подтверждён default block в журнале Xray; браузерный тест не запускается')
PY
printf 'Container: m3t-xray-routing-test\nImage: %s\nSHA: %s\nStarted: %s\n' "$XRAY_IMAGE" "$GITHUB_SHA" "$(date -u +%FT%TZ)" > "$evidence/deployment.txt"
cat "$evidence/deployment.txt" >> "${GITHUB_STEP_SUMMARY:-/dev/null}"
node "$root/source/xray-test/browse.cjs" "$root/source/routing/sites.txt" "$root/source/xray-test/required-sites.json" "$evidence" "socks5://127.0.0.1:$port"
