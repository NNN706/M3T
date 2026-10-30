#!/usr/bin/env bash
# Bash 3.2+, curl, jq 1.6+, nc. DNS A records (IPv4).
set -euo pipefail
export LC_ALL=C
usage() {
  cat <<'HELP'
Usage: SubnetResolve.sh [-parse] [-v] [-4] [-s] [domain-or-URL ...]
  No arguments: enter domains or HTTP(S) URLs separated by spaces.
  -parse  Discover site request domains with headless Chromium, then DNS/BGP.
  -v  Detailed progress log and complete Check-Host node metadata.
  -4  Output only unique IPv4 BGP prefixes: {"ip":[...]}.
  -s  Never ask to save and never save resolved.json.
  -h  Show help.
Default: DNS A records; group by (ASN, prefix), ask to save (default no).
JSON goes to stdout; prompts, diagnostics and report URL go to stderr.
Exit: 0 complete, 1 fatal error, 2 usage, 3 partial DNS/BGP coverage.
HELP
}
progress_active=0
finish_progress() {
  if [ "$progress_active" -eq 1 ]; then printf '\n' >&2; progress_active=0; fi
}
die() { finish_progress; printf 'Ошибка: %s\n' "$*" >&2; exit 1; }
verbose=0; prefixes=0; silent=0; parse=0
args=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    -parse|--parse) parse=1 ;;
    --) shift; while [ "$#" -gt 0 ]; do args+=("$1"); shift; done; break ;;
    -*)
      flags=${1#-}
      [ -n "$flags" ] || { usage >&2; exit 2; }
      while [ -n "$flags" ]; do
        flag=${flags:0:1}; flags=${flags:1}
        case "$flag" in
          v) verbose=1 ;; 4) prefixes=1 ;; s) silent=1 ;; h) usage; exit 0 ;;
          *) usage >&2; exit 2 ;;
        esac
      done ;;
    *) args+=("$1") ;;
  esac
  shift
done
set -- ${args[@]+"${args[@]}"}
# Install only missing tools. Package-manager output must not contaminate JSON.
ensure_dependencies() {
  local dependency manager package seen existing
  local missing=() packages=() elevate=() required=(curl jq nc mktemp mkfifo mkdir cat cp mv rm sleep wc tr)
  if [ "$parse" -eq 1 ]; then required+=(node npm); fi
  for dependency in "${required[@]}"; do
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
      node|npm)
        if [ "$manager" = brew ]; then package=node
        elif [ "$dependency" = node ]; then package=nodejs
        else package=npm; fi ;;
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
if [ "$#" -eq 0 ]; then
  printf 'Введите домены или URL через пробел: ' >&2
  input_line=''
  IFS= read -r input_line || die 'Домены не введены.'
  inputs=()
  IFS=$' \t' read -r -a inputs <<< "$input_line"
  [ "${#inputs[@]}" -gt 0 ] || die 'Домены не введены.'
else
  inputs=("$@")
fi
# Parse all inputs before making requests. Strip only HTTP(S) URL components.
normalize_domain() {
  local value authority port
  value=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
  case "$value" in
    http://*|https://*)
      authority=${value#*://}
      authority=${authority%%[/?#]*}
      # Credentials are not needed for DNS and must never be logged.
      authority=${authority##*@}
      case "$authority" in
        *:*)
          port=${authority##*:}
          [[ "$port" =~ ^[0-9]{1,5}$ ]] || die 'Некорректный порт в URL.'
          [ "$((10#$port))" -ge 1 ] && [ "$((10#$port))" -le 65535 ] || die 'Некорректный порт в URL.'
          authority=${authority%:*} ;;
      esac
      value=$authority ;;
    *://*) die 'Поддерживаются только HTTP(S) URL или доменные имена.' ;;
  esac
  value=${value%.}
  [ -n "$value" ] && [ "${#value}" -le 253 ] || die 'Некорректный домен или URL.'
  jq -en --arg d "$value" '$d | split(".") | length >= 2 and all(.[]; length <= 63 and test("^[a-z0-9]([a-z0-9-]*[a-z0-9])?$"))' >/dev/null || die 'Некорректный домен; IDN вводите в punycode.'
  printf '%s\n' "$value"
}
domains=()
for input in "${inputs[@]}"; do
  domain=$(normalize_domain "$input") || exit 1
  duplicate=0
  if [ "${#domains[@]}" -gt 0 ]; then
    for existing in "${domains[@]}"; do [ "$existing" != "$domain" ] || duplicate=1; done
  fi
  [ "$duplicate" -eq 1 ] || domains+=("$domain")
done
unset input input_line
batch=$(mktemp -d "${TMPDIR:-/tmp}/SubnetResolve.XXXXXXXX")
tmp=$batch
ncpid=''
http_pid=''
parse_pid=''
started=$SECONDS
stage='Check-Host: создание проверки'
progress() {
  if [ "$verbose" -eq 1 ]; then
    printf '[%3ds] %s\n' "$((SECONDS - started))" "$*" >&2
  elif [ -t 2 ]; then
    printf '\r\033[2K[%3ds] %s' "$((SECONDS - started))" "$*" >&2
    progress_active=1
  fi
}
cleanup() {
  if [ -n "$parse_pid" ]; then kill "$parse_pid" 2>/dev/null || :; wait "$parse_pid" 2>/dev/null || :; fi
  finish_progress
  if [ -n "$http_pid" ]; then kill "$http_pid" 2>/dev/null || :; wait "$http_pid" 2>/dev/null || :; fi
  if [ -n "$ncpid" ]; then kill "$ncpid" 2>/dev/null || :; wait "$ncpid" 2>/dev/null || :; fi
  rm -rf "$batch"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
get_json() {
  local rc=0 tick=0
  curl -fsS --connect-timeout 2 --max-time 2 -H 'Accept: application/json' "$@" &
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
# Optional browser capture; runtime is reused, never installed for ordinary DNS mode.
if [ "$parse" -eq 1 ]; then
  node -e 'if(Number(process.versions.node.split(".")[0]) < 20) process.exit(1)' || die '-parse требует Node.js 20 или новее.'
  runtime="${XDG_CACHE_HOME:-$HOME/.cache}/SubnetResolve/playwright-1.64.1"
  mkdir -p "$runtime" || die 'Не удалось создать кеш Playwright.'
  export SUBNET_PLAYWRIGHT="$runtime/node_modules/playwright"
  if ! node -e 'if(require(process.env.SUBNET_PLAYWRIGHT + "/package.json").version !== "1.64.1") process.exit(1)' 2>/dev/null; then
    finish_progress
    printf 'Устанавливаем Playwright для -parse...\n' >&2
    npm install --prefix "$runtime" --no-audit --no-fund --ignore-scripts playwright@1.64.1 >&2 || die 'Не удалось установить Playwright.'
  fi
  cat > "$batch/parse.cjs" <<'SUBNET_PARSE_JS'
const fs = require('node:fs');
const { chromium } = require(process.env.SUBNET_PLAYWRIGHT);
const [inputPath, outputPath, progressPath] = process.argv.slice(2);
const sleep = ms => new Promise(r => setTimeout(r, ms));
const domains = new Set(), pages = [];
const hostname = raw => {
  try {
    const u = new URL(raw);
    if (!['http:', 'https:', 'ws:', 'wss:'].includes(u.protocol)) return;
    const h = u.hostname.toLowerCase().replace(/\.$/, '');
    if (/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(h) && !/^\d+(\.\d+){3}$/.test(h)) return h;
  } catch {}
};
let browser;
async function main() {
  browser = await chromium.launch({headless: true});
  if (process.env.SUBNET_PROBE === '1') { await browser.close(); return; }
  const seeds = JSON.parse(fs.readFileSync(inputPath, 'utf8'));
  for (let i = 0; i < seeds.length; i++) {
    const seed = new URL(seeds[i]);
    // Do not use or persist URL credentials; paths and queries are needed to load the page.
    seed.username = ''; seed.password = '';
    const origin = hostname(seed.href);
    if (origin) domains.add(origin);
    const seen = new Set(), errors = new Set();
    const context = await browser.newContext({viewport:{width:1365,height:900},acceptDownloads:false});
    const record = raw => { const h = hostname(raw); if(h) { domains.add(h); seen.add(h); } };
    context.on('request', req => record(req.url()));
    context.on('page', p => p.on('websocket', ws => record(ws.url())));
    const page = await context.newPage();
    fs.writeFileSync(progressPath, `${i+1}/${seeds.length}: ${origin}; загрузка и прокрутка`);
    let timeout;
    const run = async () => {
      try {
        const response = await page.goto(seed.href, {waitUntil:'domcontentloaded',timeout:30000});
        if(response && response.status() >= 400) errors.add(`HTTP ${response.status()}`);
      } catch(e) { errors.add(e.name === 'TimeoutError' ? 'navigation_timeout' : 'navigation_failed'); }
      for(let step=0;step<10;step++) {
        await page.evaluate(() => window.scrollBy(0, Math.max(600, innerHeight))).catch(() => {});
        await sleep(1000);
        fs.writeFileSync(progressPath, `${i+1}/${seeds.length}: ${origin}; найдено доменов: ${seen.size}`);
      }
    };
    try {
      await Promise.race([run(), new Promise((_,reject) => {timeout=setTimeout(()=>reject(new Error('capture_timeout')),45000);})]);
    } catch { errors.add('capture_timeout'); }
    finally { clearTimeout(timeout); await context.close(); }
    pages.push({site:origin, domains:[...seen].sort(), errors:[...errors]});
  }
  await browser.close();
  fs.writeFileSync(outputPath, JSON.stringify({domains:[...domains].sort(),pages,complete:pages.every(p=>!p.errors.length)}));
}
process.on('SIGTERM',()=>{ if(browser) browser.close().finally(()=>process.exit(143)); else process.exit(143); setTimeout(()=>process.exit(143),2000).unref(); });
main().catch(e => {console.error('Chromium: ' + (process.env.SUBNET_PROBE === '1' ? e.message : 'не удалось завершить сбор')); process.exitCode=1; if(browser) browser.close();});
SUBNET_PARSE_JS
  if ! SUBNET_PROBE=1 node "$batch/parse.cjs" 2> "$batch/browser-error"; then
    finish_progress
    printf 'Устанавливаем Chromium и необходимые библиотеки...\n' >&2
    if command -v apt-get >/dev/null 2>&1; then
      node "$runtime/node_modules/playwright/cli.js" install --with-deps --only-shell chromium >&2 || die 'Не удалось установить Chromium; проверьте доступ к sudo и пакетному менеджеру.'
    else
      node "$runtime/node_modules/playwright/cli.js" install --only-shell chromium >&2 || die 'Не удалось установить Chromium.'
    fi
    SUBNET_PROBE=1 node "$batch/parse.cjs" 2> "$batch/browser-error" || { cat "$batch/browser-error" >&2; die 'Chromium не запускается: проверьте системные библиотеки и поддержку ОС.'; }
  fi
  printf '%s\n' "${inputs[@]}" | jq -Rs 'split("\n") | map(select(length>0) | if test("^https?://"; "i") then . else "https://" + . end) | unique' > "$batch/seeds.json"
  node "$batch/parse.cjs" "$batch/seeds.json" "$batch/discovery.json" "$batch/parse-progress" &
  parse_pid=$!
  while kill -0 "$parse_pid" 2>/dev/null; do
    detail='запуск браузера'
    if [ -s "$batch/parse-progress" ]; then detail=$(cat "$batch/parse-progress"); fi
    progress "Сбор доменов: $detail"
    sleep 1
  done
  wait "$parse_pid" || die 'Не удалось собрать домены сайта.'
  parse_pid=''
  jq -e '.domains | length > 0' "$batch/discovery.json" >/dev/null || die 'Браузер не обнаружил домены.'
  domains=()
  while IFS= read -r domain; do domains+=("$domain"); done < <(jq -r '.domains[]' "$batch/discovery.json")
  progress "Сбор завершён; уникальных доменов: ${#domains[@]}"
fi
unset inputs
index=0
observation_files=()
for domain in "${domains[@]}"; do
  index=$((index + 1))
  tmp="$batch/domain-$index"
  mkdir "$tmp"
  http_timeout=20
  stage="[$index/${#domains[@]}] $domain: создание проверки"
progress "Запрашиваем DNS A для $domain..."
if ! get_json -G --data-urlencode "host=$domain" https://check-host.net/check-dns > "$tmp/check.json" ||
   ! jq -e '.ok == 1 and (.request_id | type == "string" and test("^[A-Za-z0-9]+$")) and (.nodes | type == "object" and length > 0) and (.permanent_link | type == "string" and startswith("https://check-host.net/check-report/"))' "$tmp/check.json" >/dev/null; then
  printf '{"nodes":{},"permanent_link":null,"request_error":"Check-Host: ошибка создания проверки (HTTP/JSON/API; сетевой тайм-аут 2 с)"}\n' > "$tmp/check.json"
  printf '[]\n' > "$tmp/nodes.json"
  printf '[]\n' > "$tmp/observations.json"
  observation_files+=("$tmp/observations.json")
  continue
fi
request_id=$(jq -r .request_id "$tmp/check.json")
if [ "$verbose" -eq 1 ]; then
  printf 'Отчёт: %s\n' "$(jq -r .permanent_link "$tmp/check.json")" >&2
fi
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
  stage="[$index/${#domains[@]}] $domain: ответили $answered/$node_total узлов; попытка $((attempt + 1))/20"
  if get_json "https://check-host.net/check-result/$request_id" > "$tmp/next.json" && jq -e 'type == "object"' "$tmp/next.json" >/dev/null; then
    mv "$tmp/next.json" "$tmp/dns.json"
    answered=$(jq --slurpfile c "$tmp/check.json" '. as $r | [$c[0].nodes | keys[] | select($r[.] != null)] | length' "$tmp/dns.json")
    found=$(jq '[.. | objects | .A? | arrays | .[] | strings] | unique | length' "$tmp/dns.json")
    progress "[$index/${#domains[@]}] $domain: ответили $answered/$node_total узлов; уникальных A-адресов: $found"
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
  observation_files+=("$tmp/observations.json")
done
tmp=$batch
jq -s 'add | unique' "${observation_files[@]}" > "$tmp/observations.json"
# Deduplicate across ALL domains before the single Bulk WHOIS request.
jq -r '[.[].ip] | unique[]' "$tmp/observations.json" > "$tmp/ips"
if [ -s "$tmp/ips" ]; then
progress "Запрашиваем BGP.tools; уникальных IP: $(wc -l < "$tmp/ips" | tr -d ' ')..."
# Keep stdin open until the server closes: macOS nc can exit too early at EOF.
mkfifo "$tmp/input"
exec 3<> "$tmp/input"
nc -w 2 bgp.tools 43 < "$tmp/input" > "$tmp/bgp.txt" &
ncpid=$!
{ printf 'begin\nverbose\n'; cat "$tmp/ips"; printf 'end\n'; } >&3
for ((second=0; second<2; second++)); do
  kill -0 "$ncpid" 2>/dev/null || break
  if [ "$((second % 2))" -eq 0 ]; then progress "BGP.tools: ожидание ответа"; fi
  sleep 1
done
if kill -0 "$ncpid" 2>/dev/null; then
  kill "$ncpid" 2>/dev/null || :
  wait "$ncpid" 2>/dev/null || :
  finish_progress
  printf 'BGP.tools: время ожидания истекло; проверяем полученные записи.\n' >&2
else
  wait "$ncpid" || { finish_progress; printf 'BGP.tools: ошибка соединения; проверяем полученные записи.\n' >&2; }
fi
ncpid=''
exec 3>&-
else
  : > "$tmp/bgp.txt"
fi
jq -Rn '
  [inputs | split("|") | map(gsub("^\\s+|\\s+$"; "")) |
   select(length >= 7) | select(.[0] | test("^[0-9]+$")) |
   select(.[2] | test("^([0-9]{1,3}\\.){3}[0-9]{1,3}/([0-9]|[12][0-9]|3[0-2])$")) |
   {ip: .[1], asn: ("AS" + .[0]), prefix: .[2], country: .[3], registry: .[4],
    allocated: (if .[5] == "0001-01-01" or .[5] == "" then null else .[5] end),
    as_name: (.[6:] | join(" | "))}] | unique
' < "$tmp/bgp.txt" > "$tmp/routes.json"
index=0
full_files=()
for domain in "${domains[@]}"; do
  index=$((index + 1))
  tmp="$batch/domain-$index"
jq -n --arg domain "$domain" --argjson verbose "$verbose" \
  --slurpfile c "$tmp/check.json" --slurpfile n "$tmp/nodes.json" \
  --slurpfile o "$tmp/observations.json" --slurpfile b "$batch/routes.json" '
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
   errors: ((if $c[0].request_error then [{error: "check_request_failed", message: $c[0].request_error}] else [] end) + [$n[0][] | select(.ips | length == 0) |
       . as $n | ($c[0].nodes[.node]) as $details |
       ([.response | .. | objects | (.message?, .error?) | strings] | unique) as $messages |
       {check_host: .node, country: $details[1], city: $details[2],
        error: (if .response == null then "no_response"
                elif ($messages | join(" ") | test("timeout|timed out"; "i")) then "node_timeout"
                elif ($messages | length > 0) then "node_error" else "no_A_records" end),
        message: (if .response == null then "Узел не предоставил результат до завершения опроса"
                  elif ($messages | length > 0) then ($messages | join("; "))
                  else "Узел ответил, но не вернул IPv4 A-записи" end), response: .response}] +
     ([$o[0][].ip] | unique | map(. as $ip | select(all($routes[]; .ip != $ip)) | {ip: ., error: "No valid BGP route returned"}))),
   permanent_link: $c[0].permanent_link} |
  . + {complete: (.errors | length == 0)}
' > "$tmp/full.json"
  full_files+=("$tmp/full.json")
done
tmp=$batch
jq -s '{domains: ., complete: all(.[]; .complete)}' "${full_files[@]}" > "$tmp/batch.json"

status=0
if [ "$parse" -eq 1 ] && ! jq -e .complete "$batch/discovery.json" >/dev/null; then
  status=3
  finish_progress
  printf 'Браузер: сбор неполный (код выхода 3).\n' >&2
  jq -r '.pages[] | select(.errors|length>0) | "[\(.site)] \(.errors|join("; "))"' "$batch/discovery.json" >&2
fi
if ! jq -e .complete "$tmp/batch.json" >/dev/null; then
  status=3
  finish_progress
  printf 'Внимание: результат неполный (код выхода 3).\n' >&2
  jq -r '.domains[] | .domain as $d | .errors[] |
    "[\($d)] \(.check_host // .ip // "Check-Host") [\(.country // "—"), \(.city // "—")]: \(.error) — \(.message // "BGP.tools не вернул пригодный маршрут")"' "$tmp/batch.json" >&2
  if [ "$verbose" -eq 1 ]; then
    jq -c '.domains[] | .domain as $d | .errors[] | {domain: $d} + .' "$tmp/batch.json" >&2
  fi
fi
if [ "${#domains[@]}" -eq 1 ]; then
  jq '.domains[0]' "$tmp/batch.json" > "$tmp/full.json"
else
  cp "$tmp/batch.json" "$tmp/full.json"
fi
if [ "$prefixes" -eq 1 ]; then
  jq '{ip: ([.domains[].results[].prefix] | unique | sort_by(split("/") | (.[0] | split(".") | map(tonumber)) + [.[1]|tonumber]))}' "$tmp/batch.json" > "$tmp/output.json"
else
  cp "$tmp/full.json" "$tmp/output.json"
fi
if [ "$parse" -eq 1 ]; then
  if [ "$prefixes" -eq 1 ]; then
    jq --slurpfile d "$batch/discovery.json" '. + {domain: ($d[0].domains | map("domain:" + .))}' "$tmp/output.json" > "$tmp/parsed-output.json"
  else
    jq --slurpfile d "$batch/discovery.json" '. + {domain: ($d[0].domains | map("domain:" + .)), discovery: $d[0], complete: (.complete and $d[0].complete)}' "$tmp/batch.json" > "$tmp/parsed-output.json"
  fi
  mv "$tmp/parsed-output.json" "$tmp/output.json"
fi
if [ "$status" -eq 0 ]; then
  progress "Готово; групп ASN/prefix: $(jq '[.domains[].results[]] | length' "$tmp/batch.json")"
else
  progress "Получен неполный результат; групп ASN/prefix: $(jq '[.domains[].results[]] | length' "$tmp/batch.json")"
fi
finish_progress
if [ "$verbose" -eq 0 ]; then
  jq -r '.domains[] | select(.permanent_link != null) | "Отчёт (\(.domain)): \(.permanent_link)"' "$tmp/batch.json" >&2
fi
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
