#!/usr/bin/env bash
set -euo pipefail

: "${XRAY_IMAGE:?Set the pinned official Xray image in the workflow}"
[[ $XRAY_IMAGE =~ ^ghcr\.io/xtls/xray-core:[a-zA-Z0-9_.-]+@sha256:[a-f0-9]{64}$ ]]
root=$(cd "$(dirname "$0")/../.." && pwd)
evidence=${XRAY_EVIDENCE:-"${RUNNER_TEMP:?}/xray-evidence"}
mkdir -p "$evidence"
container_state_dir=$(mktemp -d "$evidence/container.XXXXXX")
cidfile="$container_state_dir/id"
cleanup() {
  local status=$? container
  if [ -s "$cidfile" ]; then
    container=$(cat "$cidfile")
    if [[ $container =~ ^[a-f0-9]{64}$ ]]; then
      docker logs --timestamps "$container" > "$evidence/xray.log" 2>&1 || true
      docker inspect --format '{{json .State}}' "$container" > "$evidence/container-state.json" 2>/dev/null || true
      docker rm -f "$container" >/dev/null || true
      rm -f "$cidfile"
    fi
  fi
  rmdir "$container_state_dir" 2>/dev/null || true
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP

if ! docker info --format '{{.ServerVersion}}'; then
  echo 'Docker недоступен пользователю раннера. Проверьте daemon и доступ к Docker socket на Admiralteskiy.' >&2
  exit 1
fi
node "$root/source/xray-test/prepare.cjs" "$root/Templates/Routing-(RU-Direct)/routing-ru.json" "$evidence"
chmod 644 "$evidence/config.json"
config_mount="$evidence/config.json:/etc/xray/config.json:ro"
docker pull "$XRAY_IMAGE"
docker run --rm --network none -v "$config_mount" "$XRAY_IMAGE" run -test -config /etc/xray/config.json

container=$(docker run --detach --cidfile "$cidfile" --publish 127.0.0.1::10808   --label "m3t.sha=${GITHUB_SHA:-local}" --label "m3t.run=${GITHUB_RUN_ID:-local}"   --log-driver json-file --log-opt max-size=20m --log-opt max-file=3   -v "$config_mount" "$XRAY_IMAGE" run -config /etc/xray/config.json)
binding=$(docker port "$container" 10808/tcp)
if ! [[ $binding =~ ^127\.0\.0\.1:[0-9]+$ ]]; then
  echo "Неожиданная привязка SOCKS: $binding" >&2
  exit 1
fi
port=${binding##*:}
python3 - "$port" <<'PY'
import socket
import sys
import time

for _ in range(30):
    try:
        with socket.create_connection(("127.0.0.1", int(sys.argv[1])), 0.5) as conn:
            conn.settimeout(0.5)
            conn.sendall(b"\x05\x01\x00")
            if conn.recv(2) == b"\x05\x00":
                break
    except OSError:
        pass
    time.sleep(0.5)
else:
    raise SystemExit("Xray не ответил на SOCKS5 handshake")
PY

negative=$(cat "$evidence/negative-ip")
if curl -fsS --noproxy '' --socks5-hostname "$binding" --connect-timeout 5 --max-time 10 "https://$negative/"     > /dev/null 2> "$evidence/negative-curl.log"; then
  echo 'Контрольное соединение неожиданно прошло через default block' >&2
  exit 1
fi
docker logs "$container" > "$evidence/preflight-xray.log" 2>&1
python3 - "$evidence/preflight-xray.log" "$negative" <<'PY'
import sys
with open(sys.argv[1]) as log:
    if not any(sys.argv[2] + ':443' in line and 'routing-test-socks -> block' in line for line in log):
        raise SystemExit('Не подтверждён default block в журнале Xray; браузерный тест не запускается')
PY
printf 'Container: %s\nImage: %s\nSHA: %s\nStarted: %s\n'   "$container" "$XRAY_IMAGE" "${GITHUB_SHA:-local}" "$(date -u +%FT%TZ)" > "$evidence/deployment.txt"
cat "$evidence/deployment.txt" >> "${GITHUB_STEP_SUMMARY:-/dev/null}"
node "$root/source/xray-test/browse.cjs" "$root/source/routing/sites.txt" "$root/source/xray-test/required-sites.json" "$evidence" "socks5://$binding"
