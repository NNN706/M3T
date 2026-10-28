#!/usr/bin/env bash
# Bash 3.2+, curl, jq 1.6+, nc. DNS A records (IPv4).
set -euo pipefail
export LC_ALL=C
usage() {
  cat <<'HELP'
Usage: SubnetResolve.sh [-v] [-4] [-s] [domain]
  No domain: ask interactively (ASCII / punycode hostname).
  -v  Include complete Check-Host node metadata.
  -4  Output only unique IPv4 BGP prefixes: {"ip":[...]}.
  -s  Never ask to save and never save resolved.json.
  -h  Show help.
Default: DNS A records; group by (ASN, prefix), ask to save (default no).
JSON goes to stdout; prompts, diagnostics and report URL go to stderr.
Exit: 0 complete, 1 fatal error, 2 usage, 3 partial DNS/BGP coverage.
HELP
}
die() { printf 'Ошибка: %s\n' "$*" >&2; exit 1; }
verbose=0; prefixes=0; silent=0
while getopts ':v4sh' opt; do
  case "$opt" in
    v) verbose=1 ;; 4) prefixes=1 ;; s) silent=1 ;; h) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done
shift $((OPTIND - 1))
[ "$#" -le 1 ] || { usage >&2; exit 2; }
# Install only missing tools. Package-manager output must not contaminate JSON.
ensure_dependencies() {
  local dependency manager package seen existing
  local missing=() packages=() elevate=()
  for dependency in curl jq nc mktemp mkfifo cat cp mv rm sleep wc tr; do
    if ! command -v "$dependency" >/dev/null 2>&1; then
      missing+=("$dependency")
    fi
  done
  [ "${#missing[@]}" -gt 0 ] || return 0
  printf 'Отсутствуют зависимости: %s. Начинаем установку...\n' "${missing[*]}" >&2
  manager=''
  case "${OSTYPE:-}" in
    darwin*)
      # Homebrew may be installed but absent from a non-login shell PATH.
      if ! command -v brew >/dev/null 2>&1; then
        for existing in /opt/homebrew/bin /usr/local/bin; do
          if [ -x "$existing/brew" ]; then export PATH="$existing:$PATH"; break; fi
        done
      fi
      command -v brew >/dev/null 2>&1 && manager=brew
      ;;
    *)
      for existing in apt-get dnf yum pacman apk; do
        if command -v "$existing" >/dev/null 2>&1; then manager=$existing; break; fi
      done ;;
  esac
  [ -n "$manager" ] || die 'Нет поддерживаемого пакетного менеджера. macOS: установите Homebrew (https://brew.sh); Linux: нужны apt-get, dnf, yum, pacman или apk.'
  for dependency in "${missing[@]}"; do
    case "$dependency" in
      curl|jq) package=$dependency ;;
      nc)
        case "$manager" in
          apt-get|apk) package=netcat-openbsd ;;
          dnf|yum) package=nmap-ncat ;;
          pacman) package=openbsd-netcat ;;
          brew) package=netcat ;;
        esac ;;
      *) package=coreutils ;;
    esac
    seen=0
    if [ "${#packages[@]}" -gt 0 ]; then
      for existing in "${packages[@]}"; do [ "$existing" != "$package" ] || seen=1; done
    fi
    [ "$seen" -eq 1 ] || packages+=("$package")
  done
  if [ "$manager" != brew ] && [ "$EUID" -ne 0 ]; then
    command -v sudo >/dev/null 2>&1 || die 'Для установки нужны права root или sudo.'
    elevate=(sudo)
  fi
  # Empty arrays require special handling under Bash 3.2 + nounset.
  case "$manager" in
    apt-get)
      ${elevate[@]+"${elevate[@]}"} apt-get update </dev/null >&2 || die 'Не удалось обновить список пакетов.'
      ${elevate[@]+"${elevate[@]}"} apt-get install -y "${packages[@]}" </dev/null >&2 || die 'Не удалось установить зависимости.' ;;
    dnf|yum) ${elevate[@]+"${elevate[@]}"} "$manager" install -y "${packages[@]}" </dev/null >&2 || die 'Не удалось установить зависимости.' ;;
    pacman) ${elevate[@]+"${elevate[@]}"} pacman -S --needed --noconfirm "${packages[@]}" </dev/null >&2 || die 'Не удалось установить зависимости (проверьте актуальность системы).' ;;
    apk) ${elevate[@]+"${elevate[@]}"} apk add "${packages[@]}" </dev/null >&2 || die 'Не удалось установить зависимости.' ;;
    brew) brew install "${packages[@]}" </dev/null >&2 || die 'Не удалось установить зависимости через Homebrew.' ;;
  esac
  hash -r
  for dependency in "${missing[@]}"; do
    command -v "$dependency" >/dev/null 2>&1 || die "После установки команда $dependency недоступна в PATH."
  done
}
ensure_dependencies
domain=${1-}
if [ "$#" -eq 0 ]; then
  printf 'Введите домен: ' >&2
  IFS= read -r domain || die 'Домен не введён.'
fi
domain=${domain%.}
[ -n "$domain" ] && [ "${#domain}" -le 253 ] || die 'Некорректный домен.'
jq -en --arg d "$domain" '$d | split(".") | length >= 2 and all(.[]; length <= 63 and test("^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$"))' >/dev/null || die 'Введите домен без URL/порта; IDN — в punycode.'
tmp=$(mktemp -d "${TMPDIR:-/tmp}/SubnetResolve.XXXXXXXX")
ncpid=''
http_pid=''
started=$SECONDS
stage='Check-Host: создание проверки'
progress() { printf '[%3ds] %s\n' "$((SECONDS - started))" "$*" >&2; }
cleanup() {
  if [ -n "$http_pid" ]; then kill "$http_pid" 2>/dev/null || :; wait "$http_pid" 2>/dev/null || :; fi
  if [ -n "$ncpid" ]; then kill "$ncpid" 2>/dev/null || :; wait "$ncpid" 2>/dev/null || :; fi
  rm -rf "$tmp"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
get_json() {
  local rc=0 tick=0
  curl -fsS --connect-timeout 5 --max-time "${http_timeout:-20}" -H 'Accept: application/json' "$@" &
  http_pid=$!
  while kill -0 "$http_pid" 2>/dev/null; do
    if [ "$((tick % 2))" -eq 0 ]; then progress "$stage — ожидание HTTP"; fi
    sleep 1
    tick=$((tick + 1))
  done
  wait "$http_pid" || rc=$?
  http_pid=''
  return "$rc"
}
printf 'Запрашиваем DNS A для %s...\n' "$domain" >&2
get_json -G --data-urlencode "host=$domain" https://check-host.net/check-dns > "$tmp/check.json" || die 'Check-Host: запрос не выполнен.'
jq -e '.ok == 1 and (.request_id | type == "string" and test("^[A-Za-z0-9]+$")) and (.nodes | type == "object" and length > 0) and (.permanent_link | type == "string" and startswith("https://check-host.net/check-report/"))' "$tmp/check.json" >/dev/null || die 'Check-Host: некорректный ответ.'
request_id=$(jq -r .request_id "$tmp/check.json")
printf 'Отчёт: %s\n' "$(jq -r .permanent_link "$tmp/check.json")" >&2
printf '{}\n' > "$tmp/dns.json"
# Bound the whole DNS polling phase, including slow HTTP calls.
dns_started=$SECONDS
node_total=$(jq '.nodes | length' "$tmp/check.json")
answered=0
for ((attempt=0; attempt<20; attempt++)); do
  remaining=$((60 - (SECONDS - dns_started)))
  [ "$remaining" -gt 0 ] || break
  http_timeout=$remaining
  [ "$http_timeout" -le 10 ] || http_timeout=10
  stage="DNS: ответили $answered/$node_total узлов; попытка $((attempt + 1))/20"
  if get_json "https://check-host.net/check-result/$request_id" > "$tmp/next.json" && jq -e 'type == "object"' "$tmp/next.json" >/dev/null; then
    mv "$tmp/next.json" "$tmp/dns.json"
    answered=$(jq --slurpfile c "$tmp/check.json" '. as $r | [$c[0].nodes | keys[] | select($r[.] != null)] | length' "$tmp/dns.json")
    found=$(jq '[.. | objects | .A? | arrays | .[] | strings] | unique | length' "$tmp/dns.json")
    progress "DNS: ответили $answered/$node_total узлов; уникальных A-адресов: $found"
    [ "$answered" -lt "$node_total" ] || break
  else
    progress 'DNS: ошибка запроса; повторяем до истечения лимита'
  fi
  if [ "$attempt" -lt 19 ] && [ "$((SECONDS - dns_started))" -lt 58 ]; then sleep 2; fi
done
if [ "$answered" -lt "$node_total" ]; then
  progress "DNS: ожидание завершено, ответили $answered/$node_total; продолжаем с доступными результатами"
fi
jq -n --slurpfile c "$tmp/check.json" --slurpfile r "$tmp/dns.json" '
  def ipv4: if type != "string" then false else
    test("^([0-9]{1,3}\\.){3}[0-9]{1,3}$") and (split(".") | all(.[]; tonumber <= 255)) end;
  [$c[0].nodes | keys[] as $node | $r[0][$node] as $answer |
    {node: $node, ips: ([$answer | .. | objects | .A? | arrays | .[] | select(ipv4)] | unique),
     response: $answer}]
' > "$tmp/nodes.json"
jq '[.[] | .node as $node | .ips[] | {ip: ., node: $node}] | unique' "$tmp/nodes.json" > "$tmp/observations.json"
jq -r '[.[].ip] | unique[]' "$tmp/observations.json" > "$tmp/ips"
[ -s "$tmp/ips" ] || die 'Нет DNS A-адресов: пустые ответы, ошибки или тайм-аут узлов.'
printf 'Запрашиваем BGP.tools; уникальных IP: %s...\n' "$(wc -l < "$tmp/ips" | tr -d ' ')" >&2
# Keep stdin open until the server closes: macOS nc can exit too early at EOF.
mkfifo "$tmp/input"
exec 3<> "$tmp/input"
nc -w 20 bgp.tools 43 < "$tmp/input" > "$tmp/bgp.txt" &
ncpid=$!
{ printf 'begin\nverbose\n'; cat "$tmp/ips"; printf 'end\n'; } >&3
for ((second=0; second<25; second++)); do
  kill -0 "$ncpid" 2>/dev/null || break
  if [ "$((second % 2))" -eq 0 ]; then progress "BGP.tools: ожидание ответа ($second/25 с)"; fi
  sleep 1
done
if kill -0 "$ncpid" 2>/dev/null; then
  kill "$ncpid" 2>/dev/null || :
  wait "$ncpid" 2>/dev/null || :
  die 'BGP.tools: превышено время ожидания.'
fi
wait "$ncpid" || die 'BGP.tools: соединение TCP/43 завершилось ошибкой.'
ncpid=''
exec 3>&-
[ -s "$tmp/bgp.txt" ] || die 'BGP.tools: пустой ответ.'
jq -Rn '
  [inputs | split("|") | map(gsub("^\\s+|\\s+$"; "")) |
   select(length >= 7) | select(.[0] | test("^[0-9]+$")) |
   select(.[2] | test("^([0-9]{1,3}\\.){3}[0-9]{1,3}/([0-9]|[12][0-9]|3[0-2])$")) |
   {ip: .[1], asn: ("AS" + .[0]), prefix: .[2], country: .[3], registry: .[4],
    allocated: (if .[5] == "0001-01-01" or .[5] == "" then null else .[5] end),
    as_name: (.[6:] | join(" | "))}] | unique
' < "$tmp/bgp.txt" > "$tmp/routes.json"
jq -n --arg domain "$domain" --argjson verbose "$verbose" \
  --slurpfile c "$tmp/check.json" --slurpfile n "$tmp/nodes.json" \
  --slurpfile o "$tmp/observations.json" --slurpfile b "$tmp/routes.json" '
  # Reject unrelated/malformed ranges, including a prefix not containing its IP.
  def ipnum: split(".") | map(tonumber) | if length == 4 and all(.[]; . >= 0 and . <= 255) then reduce .[] as $v (0; . * 256 + $v) else error("Invalid IPv4") end;
  [$b[0][] | . as $route | select(any($o[0][]; .ip == $route.ip)) |
   (.prefix | split("/")) as $p | pow(2; 32 - ($p[1]|tonumber)) as $size |
   select(try (((.ip|ipnum) / $size | floor) == (($p[0]|ipnum) / $size) ) catch false)] as $routes |
  [$o[0][] | . as $obs | $routes[] | select(.ip == $obs.ip) | . + {node: $obs.node}] as $joined |
  {domain: $domain, record_type: "A",
   results: ($joined | group_by([.asn, .prefix]) | map(
     . as $group | .[0] | {asn, as_name, prefix, country, registry, allocated} +
     {ips: ([$group[].ip] | unique), check_host: ([$group[].node] | unique),
      resolutions: ($group | group_by(.ip) | map({ip: .[0].ip, check_host: ([.[].node] | unique)}))} +
     (if $verbose == 1 then {check_host_details: ([$group[].node] | unique | map(. as $node | {key: $node, value: $c[0].nodes[$node]}) | from_entries)} else {} end))),
   errors: ([$n[0][] | select(.ips | length == 0) |
       {check_host: .node, error: (if .response == null then "DNS timeout / no response" else "No valid A records" end), response: .response}] +
     ([$o[0][].ip] | unique | map(. as $ip | select(all($routes[]; .ip != $ip)) | {ip: ., error: "No valid BGP route returned"}))),
   permanent_link: $c[0].permanent_link} |
  . + {complete: (.errors | length == 0)}
' > "$tmp/full.json"
jq -e '.results | length > 0' "$tmp/full.json" >/dev/null || die 'Нет пригодных BGP-результатов.'
status=0
if ! jq -e .complete "$tmp/full.json" >/dev/null; then
  status=3
  printf 'Внимание: результат неполный (код выхода 3).\n' >&2
  jq -c '.errors[]' "$tmp/full.json" >&2
fi
if [ "$prefixes" -eq 1 ]; then
  jq '{ip: ([.results[].prefix] | unique | sort_by(split("/") | (.[0] | split(".") | map(tonumber)) + [.[1]|tonumber]))}' "$tmp/full.json" > "$tmp/output.json"
else
  cp "$tmp/full.json" "$tmp/output.json"
fi
progress "Готово; групп ASN/prefix: $(jq '.results | length' "$tmp/full.json"); код результата $status"
cat "$tmp/output.json"
if [ "$silent" -eq 0 ]; then
  printf 'Сохранить результат в resolved.json (существующий файл будет заменён)? [y/N]: ' >&2
  answer=''
  IFS= read -r answer || :
  case "$answer" in
    y|Y|yes|YES|да|Да)
      # Stage in the destination directory; replace only after explicit consent.
      save_tmp=$(mktemp './.resolved.json.XXXXXXXX') || die 'Не удалось создать файл.'
      if cp "$tmp/output.json" "$save_tmp" && mv -f "$save_tmp" resolved.json; then
        printf 'Сохранено: resolved.json\n' >&2
      else
        rm -f "$save_tmp"; die 'Не удалось сохранить resolved.json.'
      fi ;;
    *) printf 'Файл не сохранён.\n' >&2 ;;
  esac
fi
exit "$status"
