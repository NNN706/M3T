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
Failures are explained on stderr; incomplete results return a non-zero exit status for automation.
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
stage_name='Подготовка'
stage='подготовка запроса'
progress() {
  if [ "$verbose" -eq 1 ]; then
    printf '[%3ds] [%s] %s\n' "$((SECONDS - started))" "$stage_name" "$*" >&2
  elif [ -t 2 ]; then
    printf '\r\033[2K[%3ds] %s' "$((SECONDS - started))" "[$stage_name] $*" >&2
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
fetch_http() {
  local expected=$1 attempt rc tls_mode=default meta status effective redirects tcp tls first challenge locations redirect_note
  local tls_args=()
  shift
  # check/object are Check-Host API requests; site preflight keeps its TLS defaults.
  if [ "$expected" != site ]; then tls_mode=tls12; fi
  http_reason=''; http_transport_failed=0
  for attempt in 1 2; do
    rc=0; redirect_note=''
    tls_args=()
    if [ "$tls_mode" = tls12 ]; then tls_args=(--tlsv1.2 --tls-max 1.2); fi
    if [ "$verbose" -eq 1 ] && [ "$expected" != site ]; then
      if [ "$tls_mode" = tls12 ]; then progress "$stage; попытка $attempt/2; TLS 1.2"
      else progress "$stage; попытка $attempt/2; обычное согласование TLS"; fi
    else
      progress "$stage; попытка $attempt/2"
    fi
    : > "$batch/http-headers"
    : > "$batch/http-meta"
    : > "$batch/http-response"
    if [ "$expected" = site ]; then
      # Keep response bodies even on HTTP errors: challenge pages carry evidence.
      curl -sS --connect-timeout 1.5 --max-time 1.5 -L --max-redirs 50 \
        --proto '=http,https' --proto-redir '=http,https' \
        -D "$batch/http-headers" -o "$batch/http-response" \
        -w '%{http_code}\t%{url_effective}\t%{num_redirects}\t%{time_connect}\t%{time_appconnect}\t%{time_starttransfer}\n' \
        "$@" > "$batch/http-meta" 2> "$batch/http-error" &
    else
      curl ${tls_args[@]+"${tls_args[@]}"} -fsS --connect-timeout 1.5 --max-time 1.5 "$@" > "$batch/http-response" 2> "$batch/http-error" &
    fi
    http_pid=$!
    while kill -0 "$http_pid" 2>/dev/null; do
      sleep 0.1
    done
    wait "$http_pid" || rc=$?
    http_pid=''
    if [ "$expected" = site ]; then
      meta=$(cat "$batch/http-meta" | tr -d '\000-\010\013-\037\177')
      status=000; effective=''; redirects=0; tcp=0; tls=0; first=0
      IFS=$'\t' read -r status effective redirects tcp tls first <<< "$meta" || :
      # Header values are untrusted: remove control characters before diagnostics.
      locations=$(jq -Rrs 'split("\n") | map(gsub("[\u0000-\u001f\u007f]"; "")) | map(select(test("^location:"; "i")) | sub("^[^:]+: *"; "")) | join(" → ")' "$batch/http-headers")
      if [ -n "$locations" ]; then
        finish_progress
        printf '[%s] Редирект (%s): %s; конечный URL: %s\n' "$stage_name" "$stage" "$locations" "$effective" >&2
      fi
      challenge=0
      if jq -Rrse 'test("(?im)^cf-mitigated: *challenge\r?$")' "$batch/http-headers" >/dev/null; then challenge=1; fi
      if [ "$rc" -eq 0 ]; then
        case "$status" in [45][0-9][0-9]) rc=22 ;; esac
        if [ "$challenge" -eq 1 ]; then rc=22; fi
      fi
    fi
    if [ "$rc" -eq 0 ]; then
      if [ "$expected" = site ] ||
         { [ "$expected" = object ] && jq -e 'type == "object"' "$batch/http-response" >/dev/null 2>&1; } ||
         { [ "$expected" = check ] && jq -e '.ok == 1 and (.request_id | type == "string" and test("^[A-Za-z0-9]+$")) and (.nodes | type == "object" and length > 0) and (.permanent_link | type == "string" and startswith("https://check-host.net/check-report/"))' "$batch/http-response" >/dev/null 2>&1; }; then
        cat "$batch/http-response"
        return 0
      fi
      http_reason='API вернул некорректный ответ или отклонил запрос'
    else
      http_transport_failed=1
      case "$rc" in
        28) http_reason='Нет ответа за 1,5 секунды' ;;
        6) http_reason='Не удалось определить IP-адрес сервера' ;;
        7) http_reason='Не удалось подключиться к серверу' ;;
        22) http_reason='Сервер вернул HTTP-ошибку'; http_transport_failed=0
            case "$(cat "$batch/http-error")" in
              *403*) http_reason='Сайт отказал в доступе. Ресурсы страницы не загружены' ;;
              *404*) http_reason='Страница не найдена' ;;
              *429*) http_reason='Сервер ограничил частоту запросов' ;;
            esac ;;
        35) http_reason='Не удалось согласовать TLS-соединение' ;;
        60) http_reason='Не удалось проверить сертификат HTTPS' ;;
        *) http_reason='Сетевой запрос завершился ошибкой' ;;
      esac
    fi
    if [ "$expected" = site ]; then
      case "$rc" in
        22)
          case "$status" in
            401) http_reason='Страница требует авторизацию' ;;
            403) http_reason='Сайт отказал в доступе. Ресурсы страницы не загружены (HTTP 403)' ;;
            404) http_reason='Страница не найдена (HTTP 404)' ;;
            429) http_reason='Сервер ограничил частоту запросов (HTTP 429)' ;;
            [5][0-9][0-9]) http_reason="Ошибка сервера сайта (HTTP $status)" ;;
            [4][0-9][0-9]) http_reason="Сервер отклонил запрос (HTTP $status)" ;;
          esac
          if [ "$challenge" -eq 1 ]; then http_reason="Cloudflare challenge: страница проверки браузера; ресурсы сайта не загружены (HTTP $status)"; fi ;;
        47) http_reason='Превышен предел 50 редиректов: возможен цикл переходов' ;;
        28)
          if [ "${tcp:-0}" = 0.000000 ] || [ "${tcp:-0}" = 0 ]; then http_reason='Нет ответа за 1,5 секунды: не завершено подключение к серверу'
          elif [[ "$effective" = https://* ]] && { [ "${tls:-0}" = 0.000000 ] || [ "${tls:-0}" = 0 ]; }; then http_reason='Нет ответа за 1,5 секунды: не завершено TLS-согласование'
          elif [ "${first:-0}" = 0.000000 ] || [ "${first:-0}" = 0 ]; then http_reason='Нет ответа за 1,5 секунды: сервер не начал HTTP-ответ'
          else http_reason='Не завершена загрузка страницы за 1,5 секунды'; fi ;;
      esac
      if [ -n "$locations" ]; then
        redirect_note="; ошибка после редиректа, конечный URL: $effective"
        if [ "$rc" -eq 28 ]; then
          http_reason='Истёк общий лимит 1,5 секунды на переходы и загрузку страницы'
        fi
      fi
      if [ "$rc" -ne 0 ] && [ -n "$effective" ]; then
        finish_progress
        printf '[%s] %s: %s%s (попытка %s/2)\n' "$stage_name" "$effective" "$http_reason" "$redirect_note" "$attempt" >&2
      fi
    fi
    if [ "$attempt" -eq 1 ]; then
      if [ "$expected" != site ]; then
        case "$rc" in
          28|35|60) tls_mode=default ;;
        esac
      fi
      if [ "$verbose" -eq 1 ]; then progress "Причина повторной попытки: $http_reason"; fi
    fi
  done
  finish_progress
  printf '[%s] %s: %s; обе попытки не удались.\n' "$stage_name" "$stage" "$http_reason" >&2
  return 1
}
get_json() { fetch_http object -H 'Accept: application/json' "$@"; }
check_service() {
  local previous_stage=$stage previous_reason=${http_reason:-} previous_transport=${http_transport_failed:-0}
  stage='проверка доступности API Check-Host (3 узла)'
  if ! fetch_http check -H 'Accept: application/json' -G --data-urlencode 'host=https://check-host.net' --data-urlencode 'max_nodes=3' https://check-host.net/check-dns > "$batch/service-check.json"; then
    die 'API Check-Host недоступен. DNS-проверки доменов и запросы BGP.tools не запускаются.'
  fi
  stage=$previous_stage
  http_reason=$previous_reason; http_transport_failed=$previous_transport
}
bgp_exchange() {
  local ip_file=$1 target=$2 attempt tick
  : > "$target"
  for attempt in 1 2; do
    progress "$stage; попытка $attempt/2"
    rm -f "$batch/bgp-input"
    mkfifo "$batch/bgp-input"
    exec 3<> "$batch/bgp-input"
    nc -w 2 bgp.tools 43 < "$batch/bgp-input" > "$batch/bgp-attempt" 2> "$batch/bgp-error" &
    ncpid=$!
    { printf 'begin\nverbose\n'; cat "$ip_file"; printf 'end\n'; } >&3
    # nc implementations differ in fractional timeout support; the watchdog
    # limits each whole exchange to approximately 1.5 seconds on all platforms.
    for ((tick=0; tick<15; tick++)); do
      kill -0 "$ncpid" 2>/dev/null || break
      sleep 0.1
    done
    if kill -0 "$ncpid" 2>/dev/null; then kill "$ncpid" 2>/dev/null || :; fi
    wait "$ncpid" 2>/dev/null || :
    ncpid=''; exec 3>&-
    cat "$batch/bgp-attempt" >> "$target"
    # Retry missing/invalid rows; never discard successfully received routes.
    if jq -Rne --rawfile wanted "$ip_file" --rawfile raw "$target" '
      def ipnum: split(".") | map(tonumber) | if length == 4 and all(.[]; . >= 0 and . <= 255 and floor == .) then reduce .[] as $v (0; . * 256 + $v) else error("Invalid IPv4") end;
      ($raw | split("\n") | map(split("|") | map(gsub("^\\s+|\\s+$"; ""))) |
       map(select(length >= 7 and (.[0]|test("^[0-9]+$")) and (.[2]|test("^[0-9.]+/([0-9]|[12][0-9]|3[0-2])$"))) |
         select(try ((.[2]|split("/")) as $p | pow(2;32-($p[1]|tonumber)) as $size |
           ((.[1]|ipnum)/$size|floor) == (($p[0]|ipnum)/$size)) catch false) | .[1])) as $got |
      ($wanted | split("\n") | map(select(length > 0))) | all(.[]; . as $ip | $got | index($ip) != null)
    ' >/dev/null; then return 0; fi
  done
  return 1
}

# Optional browser capture; runtime is reused, never installed for ordinary DNS mode.
if [ "$parse" -eq 1 ]; then
  stage_name='Этап 1/4: доступность сайтов'
  printf '%s\n' "${inputs[@]}" | jq -Rs 'split("\n") | map(select(length>0) | if test("^https?://"; "i") then . else "https://" + . end) | unique' > "$batch/all-seeds.json"
  : > "$batch/accepted-seeds"
  : > "$batch/skipped-pages"
  while IFS= read -r seed; do
    site=$(normalize_domain "$seed")
    stage="$site: открытие страницы через curl"
    if fetch_http site "$seed" > /dev/null; then
      printf '%s\n' "$seed" >> "$batch/accepted-seeds"
    else
      jq -nc --arg site "$site" --arg message "$http_reason" '{site:$site, domains:[], skipped:true, errors:[$message + "; сайт пропущен до запуска Chromium"]}' >> "$batch/skipped-pages"
    fi
  done < <(jq -r '.[]' "$batch/all-seeds.json")
  jq -Rs 'split("\n") | map(select(length>0))' "$batch/accepted-seeds" > "$batch/seeds.json"
  if [ -s "$batch/accepted-seeds" ]; then
  stage_name='Этап 2/4: браузер'
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
    context.on('request', req => {
      record(req.url());
      const previous = req.redirectedFrom();
      if (previous) console.error(`[Этап 2/4: браузер] Редирект: ${previous.url()} → ${req.url()}`);
    });
    context.on('page', p => p.on('websocket', ws => record(ws.url())));
    const page = await context.newPage();
    fs.writeFileSync(progressPath, `${i+1}/${seeds.length}: ${origin}; загрузка и прокрутка`);
    let timeout;
    const run = async () => {
      try {
        const response = await page.goto(seed.href, {waitUntil:'domcontentloaded',timeout:30000});
        if(response && response.status() >= 400) {
          const status=response.status();
          errors.add(status === 403 ? 'Сайт отказал автоматическому браузеру в доступе. Ресурсы страницы не загружены; список доменов может содержать только адрес самого сайта.' :
            status === 401 ? 'Сайт требует авторизацию. Ресурсы закрытой страницы недоступны.' :
            status === 429 ? 'Сайт временно ограничил частоту запросов. Повторите проверку позже.' :
            status >= 500 ? 'Сервер сайта не смог загрузить страницу. Повторите проверку позже.' :
            'Не удалось загрузить страницу: сервер вернул ошибку. Проверьте адрес сайта.');
        }
      } catch(e) { errors.add(e.name === 'TimeoutError' ? 'Страница не загрузилась за 30 секунд. Собраны только запросы, появившиеся до завершения ожидания.' : 'Браузер не смог открыть страницу. Проверьте доступность сайта, сеть и сертификат HTTPS.'); }
      for(let step=0;step<10;step++) {
        await page.evaluate(() => window.scrollBy(0, Math.max(600, innerHeight))).catch(() => {});
        await sleep(1000);
        fs.writeFileSync(progressPath, `${i+1}/${seeds.length}: ${origin}; найдено доменов: ${seen.size}`);
      }
    };
    try {
      await Promise.race([run(), new Promise((_,reject) => {timeout=setTimeout(()=>reject(new Error('capture_timeout')),45000);})]);
    } catch { errors.add('Сбор запросов не завершился за 45 секунд. Список доменов неполный.'); }
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
  else
    printf '{"domains":[],"pages":[],"complete":true}\n' > "$batch/discovery.json"
  fi
  jq --slurpfile skipped "$batch/skipped-pages" '.pages += $skipped | .complete = (.complete and ($skipped|length == 0))' "$batch/discovery.json" > "$batch/discovery-next.json"
  mv "$batch/discovery-next.json" "$batch/discovery.json"
  domains=()
  while IFS= read -r domain; do domains+=("$domain"); done < <(jq -r '(.domains + [.pages[] | select(.skipped == true) | .site]) | unique[]' "$batch/discovery.json")
  progress "Сбор завершён; уникальных доменов: ${#domains[@]}"
fi
unset inputs
stage_name='Этап 3/4: DNS'
active_count=${#domains[@]}
if [ "$parse" -eq 1 ]; then active_count=$(jq '.domains|length' "$batch/discovery.json"); fi
if [ "$active_count" -gt 0 ]; then check_service; fi
index=0
observation_files=()
for domain in "${domains[@]}"; do
  index=$((index + 1))
  tmp="$batch/domain-$index"
  mkdir "$tmp"
  if [ "$parse" -eq 1 ] && ! jq -e --arg d "$domain" '.domains | index($d) != null' "$batch/discovery.json" >/dev/null; then
    printf '{"nodes":{},"permanent_link":null,"request_error":"Сайт недоступен через curl; Chromium и DNS для него не запускались"}\n' > "$tmp/check.json"
    printf '[]\n' > "$tmp/nodes.json"
    printf '[]\n' > "$tmp/observations.json"
    observation_files+=("$tmp/observations.json")
    continue
  fi
  stage="Домен $index/${#domains[@]}: $domain — отправка задания DNS в Check-Host"
progress "Запрашиваем DNS A для $domain..."
if ! fetch_http check -H 'Accept: application/json' -G --data-urlencode "host=$domain" https://check-host.net/check-dns > "$tmp/check.json" ||
   ! jq -e '.ok == 1 and (.request_id | type == "string" and test("^[A-Za-z0-9]+$")) and (.nodes | type == "object" and length > 0) and (.permanent_link | type == "string" and startswith("https://check-host.net/check-report/"))' "$tmp/check.json" >/dev/null; then
  if [ "$http_transport_failed" -eq 1 ]; then check_service; fi
  jq -n --arg message "$http_reason" '{nodes:{},permanent_link:null,request_error:("Check-Host: не удалось отправить задание DNS после двух попыток; " + $message)}' > "$tmp/check.json"
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
  stage="Домен $index/${#domains[@]}: $domain — ожидание DNS-ответов; ответили $answered/$node_total узлов; опрос $((attempt + 1))/20"
  if get_json "https://check-host.net/check-result/$request_id" > "$tmp/next.json" && jq -e 'type == "object"' "$tmp/next.json" >/dev/null; then
    mv "$tmp/next.json" "$tmp/dns.json"
    answered=$(jq --slurpfile c "$tmp/check.json" '. as $r | [$c[0].nodes | keys[] | select($r[.] != null)] | length' "$tmp/dns.json")
    found=$(jq '[.. | objects | .A? | arrays | .[] | strings] | unique | length' "$tmp/dns.json")
    progress "Домен $index/${#domains[@]}: $domain — ответили $answered/$node_total узлов; уникальных A-адресов: $found"
    [ "$answered" -lt "$node_total" ] || break
  else
    if [ "$http_transport_failed" -eq 1 ]; then check_service; fi
    jq --arg reason "$http_reason" '.poll_error = ($reason + "; не удалось получить отчёт Check-Host после двух попыток")' "$tmp/check.json" > "$tmp/check-next.json"
    mv "$tmp/check-next.json" "$tmp/check.json"
    progress 'Не удалось получить DNS-результат после двух попыток; переходим к следующему домену'
    break
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
stage_name='Этап 4/4: BGP'
if [ -s "$tmp/ips" ]; then
  printf '1.1.1.1\n' > "$batch/probe-ip"
  stage='проверка доступности BGP.tools: запрос маршрута для 1.1.1.1'
  bgp_exchange "$batch/probe-ip" "$batch/probe-bgp" || die 'BGP.tools недоступен или не вернул корректный ответ после двух попыток. Массовый запрос не запускается.'
  stage="маршруты для уникальных IP: $(wc -l < "$tmp/ips" | tr -d ' ')"
  if ! bgp_exchange "$tmp/ips" "$tmp/bgp.txt"; then
    finish_progress
    printf 'BGP.tools не вернул маршруты для части IP после двух попыток. Доступные записи будут сохранены.\n' >&2
  fi
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
   errors: ((if $c[0].request_error then [{error: "Не удалось запустить DNS-проверку", message: $c[0].request_error}] else [] end) + [$n[0][] | select(.ips | length == 0) |
       . as $n | ($c[0].nodes[.node]) as $details |
       ([.response | .. | objects | (.message?, .error?) | strings] | unique) as $messages |
       {check_host: .node, country: $details[1], city: $details[2],
        error: (if .response == null then "Узел не предоставил DNS-результат"
                elif ($messages | join(" ") | test("timeout|timed out"; "i")) then "Узел сообщил о превышении времени ожидания"
                elif ($messages | length > 0) then "Узел сообщил об ошибке DNS" else "Узел ответил без IPv4-адресов" end),
        message: (if .response == null then ($c[0].poll_error // "Узел не предоставил результат до завершения опроса")
                  elif ($messages | length > 0) then ($messages | join("; "))
                  else "Узел ответил, но не вернул IPv4 A-записи" end), response: .response}] +
     ([$o[0][].ip] | unique | map(. as $ip | select(all($routes[]; .ip != $ip)) | {ip: ., error: "BGP.tools не вернул пригодный маршрут для IP-адреса"}))),
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
  printf 'Не удалось собрать полный список доменов сайта:\n' >&2
  jq -r '.pages[] | select(.errors|length>0) | "[\(.site)] \(.errors|join("; "))"' "$batch/discovery.json" >&2
fi
if ! jq -e .complete "$tmp/batch.json" >/dev/null; then
  status=3
  finish_progress
  printf 'Для части доменов, узлов или IP не удалось получить DNS/BGP-данные:\n' >&2
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
stage_name='Результат'
if [ "$status" -eq 0 ]; then
  progress "Готово; групп ASN/prefix: $(jq '[.domains[].results[]] | length' "$tmp/batch.json")"
else
  progress "Проверка завершена с ограничениями"
  finish_progress
  printf 'Выведены только доступные данные: уникальных подсетей — %s. Полный список доменов или подсетей получить не удалось; причины указаны выше.\n' "$(jq '[.domains[].results[].prefix] | unique | length' "$tmp/batch.json")" >&2
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
