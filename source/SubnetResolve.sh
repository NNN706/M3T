#!/usr/bin/env bash
# Bash 3.2+, curl, jq 1.6+, nc. DNS A records (IPv4).
set -euo pipefail
export LC_ALL=C
usage() {
  cat <<'HELP'
Usage: SubnetResolve.sh [-parse] [-rules] [-v] [-4] [-s] [domain-or-URL ...]
  No arguments: enter domains or HTTP(S) URLs separated by spaces.
  -parse  Discover site request domains with headless Chromium, then DNS/BGP.
  -rules  Output per-service Xray rule fragments: {"rules":[{"ruleTag":...,"ip":[...]}]}.
  -v  Detailed progress log and complete Check-Host node metadata.
  -4  Output only unique IPv4 BGP prefixes: {"ip":[...]}.
  --resume-bgp FILE  Continue WHOIS lookups from a saved DNS checkpoint.
  -s  Never ask to save and never save resolved.json.
  -h  Show help.
Default: DNS A records; group by (ASN, prefix), ask to save (default no).
Set SUBNET_DNS_CONCURRENCY to 1–15 to limit simultaneous Check-Host DNS checks (default 15).
JSON goes to stdout; prompts, diagnostics and report URL go to stderr.
Failures are explained on stderr; incomplete results return a non-zero exit status for automation.
HELP
}
progress_active=0
finish_progress() {
  if [ "$progress_active" -eq 1 ]; then printf '\n' >&2; progress_active=0; fi
}
die() { finish_progress; printf 'Ошибка: %s\n' "$*" >&2; exit 1; }
verbose=0; prefixes=0; silent=0; parse=0; rules=0
resume_bgp=''
args=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    --resume-bgp)
      [ "$#" -ge 2 ] && [ -n "$2" ] || die '--resume-bgp требует путь к файлу.'
      resume_bgp=$2; shift ;;
    -parse|--parse) parse=1 ;;
    -rules|--rules) rules=1 ;;
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
if [ -n "$resume_bgp" ]; then parse=0; fi
# Install only missing tools. Package-manager output must not contaminate JSON.
ensure_dependencies() {
  local dependency manager package seen existing
  local missing=() packages=() elevate=() required=(curl jq nc mktemp mkdir cat cp mv rm sleep wc tr date)
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
if [ -n "$resume_bgp" ]; then
  [ "$#" -eq 0 ] || die 'С --resume-bgp домены берутся из файла; уберите позиционные аргументы.'
  jq -e 'type == "object" and .version == 1 and (.services | type == "array" and length > 0)
    and (.dns | type == "array" and length > 0)
    and all(.dns[]; (.domain | type == "string") and (.check | type == "object")
      and (.nodes | type == "array") and (.observations | type == "array")
      and all(.observations[]; (.ip | type == "string" and test("^([0-9]{1,3}\\.){3}[0-9]{1,3}$"))
        and (.node | type == "string")))
    and (.discovery == null or (.discovery | type == "object" and has("domains") and has("pages")))
    and (.whois | type == "string")' "$resume_bgp" >/dev/null || die 'Файл продолжения BGP повреждён или имеет неподдерживаемый формат.'
  inputs=()
  while IFS= read -r domain; do inputs+=("$domain"); done < <(jq -r '.dns[].domain' "$resume_bgp")
elif [ "$#" -eq 0 ]; then
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
printf '%s\n' "${domains[@]}" | jq -Rs 'split("\n") | map(select(length>0)) | unique' > "$batch/services.json"
checkpoint=''
bgp_complete=0
ncpid=''
http_pid=''
parse_pid=''
dns_pids=()
dns_concurrency=${SUBNET_DNS_CONCURRENCY:-15}
if ! [[ "$dns_concurrency" =~ ^([1-9]|1[0-5])$ ]]; then
  rm -rf "$batch"
  die 'SUBNET_DNS_CONCURRENCY должен быть от 1 до 15.'
fi
mkdir "$batch/check-host-cooldown"
started=$SECONDS
stage_name='Подготовка'
stage='подготовка запроса'
progress() {
  if [ "$verbose" -eq 1 ]; then
    local event_key="$stage_name|$*"
    [ "${last_progress_event:-}" != "$event_key" ] || return 0
    last_progress_event=$event_key
    printf '[%3ds] [%s] %s\n' "$((SECONDS - started))" "$stage_name" "$*" >&2
  elif [ -t 2 ] && [ "${dns_worker:-0}" -eq 0 ]; then
    local rendered term_size term_cols count row
    if [ "$progress_active" -eq 1 ] && [ "${progress_rows:-1}" -gt 1 ]; then
      printf '\r' >&2
      for ((row=1; row<progress_rows; row++)); do printf '\033[1A' >&2; done
      printf '\033[J' >&2
    else
      printf '\r\033[2K' >&2
    fi
    printf -v rendered '[%3ds] [%s] %s' "$((SECONDS - started))" "$stage_name" "$*"
    term_size=$(stty size <&2 2>/dev/null || :)
    term_cols=${term_size##* }
    if ! [[ "$term_cols" =~ ^[1-9][0-9]*$ ]]; then term_cols=${COLUMNS:-80}; fi
    if ! [[ "$term_cols" =~ ^[1-9][0-9]*$ ]]; then term_cols=80; fi
    count=$(jq -nr --arg text "$rendered" '$text|length')
    progress_rows=$(((count + term_cols - 1) / term_cols))
    [ "$progress_rows" -gt 0 ] || progress_rows=1
    printf '%s' "$rendered" >&2
    progress_active=1
  fi
}
cleanup() {
  local pid
  for pid in ${dns_pids[@]+"${dns_pids[@]}"}; do kill "$pid" 2>/dev/null || :; done
  for pid in ${dns_pids[@]+"${dns_pids[@]}"}; do wait "$pid" 2>/dev/null || :; done
  if [ -n "$parse_pid" ]; then kill "$parse_pid" 2>/dev/null || :; wait "$parse_pid" 2>/dev/null || :; fi
  finish_progress
  if [ -n "$http_pid" ]; then kill "$http_pid" 2>/dev/null || :; wait "$http_pid" 2>/dev/null || :; fi
  if [ -n "$ncpid" ]; then kill "$ncpid" 2>/dev/null || :; wait "$ncpid" 2>/dev/null || :; fi
  if [ -n "$checkpoint" ]; then
    if [ "$bgp_complete" -eq 1 ]; then
      rm -f "$checkpoint"
    else
      save_bgp_checkpoint || :
      if [ -s "$checkpoint" ]; then printf 'DNS/BGP сохранены для продолжения. Добавьте к команде --resume-bgp %q (без списка доменов).\n' "$checkpoint" >&2; fi
    fi
  fi
  rm -rf "$batch"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
site_progress() {
  if [ "$verbose" -eq 1 ] || [ -t 2 ]; then
    progress "$*"
  else
    printf '[%3ds] [%s] %s\n' "$((SECONDS - ${started:-$SECONDS}))" "$stage_name" "$*" >&2
  fi
}
wait_for_check_host() {
  local now deadline file
  while :; do
    now=$(date +%s)
    for file in "$batch/check-host-cooldown/"*.until; do
      [ -f "$file" ] || continue
      read -r deadline < "$file"
      if [ "$deadline" -gt "$now" ]; then
        if [ "$wait_started" -lt 0 ]; then wait_started=$SECONDS; fi
        sleep 1
        continue 2
      fi
    done
    return 0
  done
}

fetch_http() {
  local expected=$1 attempt rc tls_mode=default meta status effective redirects tcp tls first challenge locations request_url wait_delay=5 wait_left wait_started=-1
  local tls_args=()
  local request_dir=${http_dir:-$batch} rate_retries=0 retry_after retry_epoch deadline
  local cooldown_file="$batch/check-host-cooldown/${request_dir##*/}.until"
  local request_stage=$stage
  shift
  for request_url do :; done
  http_wait_seconds=${http_wait_seconds:-0}
  while :; do
  # check/object are Check-Host API requests; site preflight keeps its TLS defaults.
  if [ "$expected" != site ]; then tls_mode=tls12; fi
  http_reason=''; http_transport_failed=0
  for attempt in 1 2; do
    if [ "$expected" != site ]; then wait_for_check_host; fi
    rc=0
    tls_args=()
    if [ "$tls_mode" = tls12 ]; then tls_args=(--tlsv1.2 --tls-max 1.2); fi
    if [ "$verbose" -eq 1 ] && [ "$expected" != site ]; then
      if [ "$expected" != object ] || [ "$attempt" -gt 1 ] || [ "$wait_started" -ge 0 ]; then
      if [ "$tls_mode" = tls12 ]; then progress "$stage; попытка $attempt/2; TLS 1.2"
      else progress "$stage; попытка $attempt/2; обычное согласование TLS"; fi
      fi
    elif [ "$expected" != site ] || [ "$verbose" -eq 0 ]; then
      progress "$stage; попытка $attempt/2"
    fi
    : > "$request_dir/http-headers"
    : > "$request_dir/http-meta"
    : > "$request_dir/http-response"
    if [ "$expected" = site ]; then
      # Keep response bodies even on HTTP errors: challenge pages carry evidence.
      curl -sS --connect-timeout 2 --max-time 2 -L --max-redirs 50 \
        --proto '=http,https' --proto-redir '=http,https' \
        -D "$request_dir/http-headers" -o "$request_dir/http-response" \
        -w '%{http_code}\t%{url_effective}\t%{num_redirects}\t%{time_connect}\t%{time_appconnect}\t%{time_starttransfer}\n' \
        "$@" > "$request_dir/http-meta" 2> "$request_dir/http-error" &
    else
      curl ${tls_args[@]+"${tls_args[@]}"} -fsS -D "$request_dir/http-headers" --connect-timeout 1.5 --max-time 1.5 "$@" > "$request_dir/http-response" 2> "$request_dir/http-error" &
    fi
    http_pid=$!
    while kill -0 "$http_pid" 2>/dev/null; do
      sleep 0.1
    done
    wait "$http_pid" || rc=$?
    http_pid=''
    if [ "$expected" != site ] && [ "$rc" -eq 22 ] &&
       jq -Rse '[splits("\n") | select(test("^HTTP/[^ ]+ ")) | split(" ")[1] | rtrimstr("\r")] | last == "429"' "$request_dir/http-headers" >/dev/null; then
      retry_after=$(jq -Rrs '[splits("\n") | select(test("^retry-after:"; "i")) |
        sub("^[^:]+:[ \t]*"; "") | gsub("[ \t\r]+$"; "")] | last // ""' "$request_dir/http-headers")
      deadline=$(date +%s)
      if [[ "$retry_after" =~ ^[0-9]{1,9}$ ]]; then
        retry_after=$((10#$retry_after))
      else
        retry_epoch=$(date -u -d "$retry_after" +%s 2>/dev/null ||
          date -u -j -f '%a, %d %b %Y %H:%M:%S GMT' "$retry_after" +%s 2>/dev/null || :)
        if [[ "$retry_epoch" =~ ^[0-9]+$ ]] && [ "$retry_epoch" -gt "$deadline" ]; then
          retry_after=$((retry_epoch - deadline))
        else
          retry_after=$((5 << rate_retries))
        fi
      fi
      printf '%s\n' "$((deadline + retry_after + 1))" > "$cooldown_file.tmp"
      mv "$cooldown_file.tmp" "$cooldown_file"
      http_reason='Check-Host вернул HTTP 429'
      if [ "$rate_retries" -eq 3 ]; then break 2; fi
      rate_retries=$((rate_retries + 1))
      progress "$stage; HTTP 429; общая пауза $retry_after с; повтор $rate_retries/3"
      continue 2
    fi
    if [ "$expected" = site ]; then
      meta=$(cat "$request_dir/http-meta" | tr -d '\000-\010\013-\037\177')
      status=000; effective=''; redirects=0; tcp=0; tls=0; first=0
      IFS=$'\t' read -r status effective redirects tcp tls first <<< "$meta" || :
      # Header values are untrusted: remove control characters before diagnostics.
      locations=$(jq -Rrs --arg start "$request_url" '
        def host: ((try (capture("^(?:https?:)?//(?:[^/?#@]*@)?(?<h>\\[[^]]+\\]|[^/:?#]+)"; "i").h | ascii_downcase) catch "") // "");
        ($start | host) as $initial |
        split("\n") | map(gsub("[\u0000-\u001f\u007f]"; "")) |
        map(select(test("^location:"; "i")) | sub("^[^:]+: *"; "")) |
        if length == 0 then "" else
          reduce .[] as $url ({current:$initial,chain:[$initial]};
            ($url|host) as $next | .current = (if $next == "" then .current else $next end) | .chain += [.current]) |
          .chain | join(" → ") end
      ' "$request_dir/http-headers")
      challenge=0
      if jq -Rrse 'test("(?im)^cf-mitigated: *challenge\r?$")' "$request_dir/http-headers" >/dev/null; then challenge=1; fi
      if [ "$rc" -eq 0 ]; then
        case "$status" in [45][0-9][0-9]) rc=22 ;; esac
        if [ "$challenge" -eq 1 ]; then rc=22; fi
      fi
    fi
    if [ "$rc" -eq 0 ]; then
      if [ "$expected" = site ] ||
         { [ "$expected" = object ] && jq -e 'type == "object"' "$request_dir/http-response" >/dev/null 2>&1; } ||
         { [ "$expected" = check ] && jq -e '.ok == 1 and (.request_id | type == "string" and test("^[A-Za-z0-9]+$")) and (.nodes | type == "object" and length > 0) and (.permanent_link | type == "string" and startswith("https://check-host.net/check-report/"))' "$request_dir/http-response" >/dev/null 2>&1; }; then
        if [ "$expected" = site ]; then
          site_progress "$request_stage; попытка $attempt/2${locations:+; Редирект: $locations}; HTTP $status"
        fi
        if [ "$wait_started" -ge 0 ]; then
          http_wait_seconds=$((http_wait_seconds + SECONDS - wait_started))
          progress "Check-Host снова отвечает; $stage"
        fi
        cat "$request_dir/http-response"
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
            case "$(cat "$request_dir/http-error")" in
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
          if [ "${tcp:-0}" = 0.000000 ] || [ "${tcp:-0}" = 0 ]; then http_reason='Нет ответа за 2 секунды: не завершено подключение к серверу'
          elif [[ "$effective" = https://* ]] && { [ "${tls:-0}" = 0.000000 ] || [ "${tls:-0}" = 0 ]; }; then http_reason='Нет ответа за 2 секунды: не завершено TLS-согласование'
          elif [ "${first:-0}" = 0.000000 ] || [ "${first:-0}" = 0 ]; then http_reason='Нет ответа за 2 секунды: сервер не начал HTTP-ответ'
          else http_reason='Не завершена загрузка страницы за 2 секунды'; fi ;;
      esac
      if [ -n "$locations" ]; then
        if [ "$rc" -eq 28 ]; then
          http_reason='Истёк общий лимит 2 секунды на переходы и загрузку страницы'
        fi
      fi
      site_progress "$request_stage; попытка $attempt/2${locations:+; Редирект: $locations}; $http_reason"
    fi
    if [ "$attempt" -eq 1 ]; then
      if [ "$expected" != site ]; then
        case "$rc" in
          28|35|60) tls_mode=default ;;
        esac
      fi
      if [ "$verbose" -eq 1 ] && [ "$expected" != site ]; then progress "Причина повторной попытки: $http_reason"; fi
    fi
  done
  if [ "$expected" != site ] && [ "$rc" -eq 28 ]; then
    if [ "$wait_started" -lt 0 ]; then wait_started=$SECONDS; fi
    progress "$stage; тайм-аут API Check-Host; Ждём $wait_delay с"
    for ((wait_left=wait_delay; wait_left>0; wait_left--)); do
      if [ "$verbose" -eq 0 ]; then
        progress "$stage; ожидание API Check-Host — повтор через $wait_left с"
      fi
      sleep 1
    done
    wait_delay=$((wait_delay * 2))
    [ "$wait_delay" -le 30 ] || wait_delay=30
  else
    break
  fi
  done
  if [ "$wait_started" -ge 0 ]; then http_wait_seconds=$((http_wait_seconds + SECONDS - wait_started)); fi
  [ "$expected" != site ] || return 1
  finish_progress
  if [ "$rate_retries" -gt 0 ] && [ "$http_reason" = 'Check-Host вернул HTTP 429' ]; then
    printf '[%s] %s: %s; исчерпаны 3 повтора.\n' "$stage_name" "$stage" "$http_reason" >&2
    return 1
  fi
  printf '[%s] %s: %s; обе попытки не удались.\n' "$stage_name" "$stage" "$http_reason" >&2
  return 1
}
get_json() { fetch_http object -H 'Accept: application/json' "$@"; }
check_service() {
  local previous_stage=$stage previous_reason=${http_reason:-} previous_transport=${http_transport_failed:-0}
  stage='проверка доступности API Check-Host (3 узла)'
  if ! fetch_http check -H 'Accept: application/json' -G --data-urlencode 'host=https://check-host.net' --data-urlencode 'max_nodes=3' https://check-host.net/check-dns > "${http_dir:-$batch}/service-check.json"; then
    die 'API Check-Host недоступен. DNS-проверки доменов и запросы BGP.tools не запускаются.'
  fi
  stage=$previous_stage
  http_reason=$previous_reason; http_transport_failed=$previous_transport
}
bgp_state() {
  local ip_file=$1 table=$2 state=$3
  jq -n --rawfile wanted "$ip_file" --rawfile raw "$table" '
    def ipnum: split(".") | map(tonumber) | if length == 4 and all(.[]; . >= 0 and . <= 255 and floor == .) then reduce .[] as $v (0; . * 256 + $v) else error("Invalid IPv4") end;
    def valid:
      length >= 7 and (.[0]|test("^[1-9][0-9]*$")) and
      (.[2]|test("^[0-9.]+/([0-9]|[12][0-9]|3[0-2])$")) and
      (try ((.[2]|split("/")) as $p | pow(2;32-($p[1]|tonumber)) as $size |
        ((.[1]|ipnum)/$size|floor) == (($p[0]|ipnum)/$size)) catch false);
    ($wanted|split("\n")|map(select(length>0))|unique) as $ips |
    ($ips|map({key:.,value:true})|from_entries) as $wanted_set |
    ($raw|split("\n")|map(split("|")|map(gsub("^\\s+|\\s+$";"")))|
      map(select(length>=7) | select(.[1] as $ip | $wanted_set[$ip]==true))) as $rows |
    ($rows|map(select(valid))) as $valid |
    ($valid|map({key:.[1],value:true})|from_entries) as $valid_set |
    ($rows|map({key:.[1],value:.})|from_entries) as $row_map |
    {routes: ($valid|map({ip:.[1],asn:("AS"+.[0]),prefix:.[2],country:.[3],registry:.[4],
      allocated:(if .[5]=="0001-01-01" or .[5]=="" then null else .[5] end),as_name:(.[6:]|join(" | "))})|unique),
     pending: [$ips[]|select($row_map[.]==null)],
     errors: [$ips[] as $ip | select($valid_set[$ip]!=true) |
       $row_map[$ip] as $row |
       {ip:$ip,error:"Не получены BGP-префикс и ASN",message:
         (if $row==null then "В ответе WHOIS нет записи для этого IP"
          elif ($row[0]=="NA" or $row[0]=="N/A" or $row[0]=="0" or $row[0]=="") and ($row[2]=="NA" or $row[2]=="N/A" or $row[2]=="") then "BGP.tools ответил, но не указал анонсируемую подсеть и ASN для этого IP"
          elif ($row[0]|test("^[1-9][0-9]*$")|not) then "BGP.tools вернул запись без корректного ASN"
          else "BGP.tools вернул некорректный BGP-префикс либо подсеть, не содержащую этот IP" end)}]}
  ' > "$state"
}
bgp_exchange() {
  local ip_file=$1 target=$2 mode=${3:-bulk} attempt rc timed_out reply_complete
  local wait_delay=5 wait_left recovering=0 cycle_timeout before_count remaining total
  local began last_data last_size size now transport_reason
  : > "$target"
  if [ "$mode" = resume ]; then
    # Retain only usable routes. Missing or invalid replies must be queried again.
    jq -r .whois "$resume_bgp" > "$batch/previous-whois"
    bgp_state "$ip_file" "$batch/previous-whois" "$batch/previous-bgp-state.json"
    jq -r '.routes[] | [.asn[2:],.ip,.prefix,.country,.registry,(.allocated // ""),.as_name] | join(" | ")'       "$batch/previous-bgp-state.json" > "$target"
  fi
  : > "$batch/bgp-unanswered"
  bgp_state "$ip_file" "$target" "$batch/bgp-state.json"
  total=$(jq '.pending|length' "$batch/bgp-state.json")
  while :; do
    jq -nr --slurpfile state "$batch/bgp-state.json" --rawfile skipped "$batch/bgp-unanswered" '
      $state[0].pending - ($skipped|split("\n")|map(select(length>0))) | .[]
    ' > "$batch/bgp-work"
    if [ ! -s "$batch/bgp-work" ]; then
      jq -e '.errors|length==0' "$batch/bgp-state.json" >/dev/null
      return $?
    fi
    jq -Rrs 'split("\n")|map(select(length>0))|.[:100][]' "$batch/bgp-work" > "$batch/bgp-request"
    cycle_timeout=0
    before_count=$(jq '.pending|length' "$batch/bgp-state.json")
    for attempt in 1 2; do
      progress "$stage; обработано: $((total - before_count))/$total; в пакете: $(wc -l < "$batch/bgp-request" | tr -d ' '); попытка $attempt/2"
      rc=0; timed_out=0; reply_complete=0
      { printf 'begin\nverbose\n'; cat "$batch/bgp-request"; printf 'end\n'; } > "$batch/bgp-payload"
      : > "$batch/bgp-attempt"
      if [[ "${OSTYPE:-}" == darwin* ]]; then
        # Apple's nc exits on stdin EOF before a delayed WHOIS reply arrives.
        # Keep stdin open through the response; the WHOIS "end" line terminates the request.
        if [ ! -p "$batch/bgp-stdin" ]; then mkfifo "$batch/bgp-stdin" || return 1; fi
        exec 8<>"$batch/bgp-stdin" || return 1
        nc -w 10 bgp.tools 43 8>&- < "$batch/bgp-stdin" > "$batch/bgp-attempt" 2> "$batch/bgp-error" &
        ncpid=$!
        cat "$batch/bgp-payload" >&8
      else
        nc -w 10 bgp.tools 43 < "$batch/bgp-payload" > "$batch/bgp-attempt" 2> "$batch/bgp-error" &
        ncpid=$!
      fi
      began=$SECONDS; last_data=$SECONDS; last_size=0
      transport_reason='тайм-аут ожидания WHOIS-ответа'
      while kill -0 "$ncpid" 2>/dev/null; do
        size=$(wc -c < "$batch/bgp-attempt" | tr -d ' ')
        if [ "$size" -gt "$last_size" ]; then
          last_data=$SECONDS; last_size=$size
          # Only complete lines can confirm that every requested IP has an answer.
          jq -Rrs 'split("\n")|.[:-1][]|select(length>0)' "$batch/bgp-attempt" > "$batch/bgp-live-lines"
          bgp_state "$batch/bgp-request" "$batch/bgp-live-lines" "$batch/bgp-live-state.json"
          if jq -e '.pending|length==0' "$batch/bgp-live-state.json" >/dev/null; then
            reply_complete=1
            kill "$ncpid" 2>/dev/null || :
            break
          fi
        fi
        now=$SECONDS
        if [ "$((now - last_data))" -ge 10 ] || [ "$((now - began))" -ge 30 ]; then
          timed_out=1
          kill "$ncpid" 2>/dev/null || :
          break
        fi
        sleep 0.1
      done
      wait "$ncpid" 2>/dev/null || rc=$?
      if [[ "${OSTYPE:-}" == darwin* ]]; then exec 8>&-; fi
      ncpid=''
      if [ "$reply_complete" -eq 1 ]; then rc=0; fi
      # Some nc variants return success on their own idle timeout.
      if [ "$reply_complete" -eq 0 ] && [ "$((SECONDS - last_data))" -ge 9 ]; then timed_out=1; fi
      if [ "$timed_out" -eq 0 ] && [ "$rc" -ne 0 ]; then transport_reason='ошибка TCP-соединения'; fi
      jq -Rrs --argjson truncated "$timed_out" '
        if $truncated==1 and (endswith("\n")|not) then split("\n")|.[:-1][] else split("\n")[] end | select(length>0)
      ' "$batch/bgp-attempt" >> "$target"
      bgp_state "$ip_file" "$target" "$batch/bgp-state.json"
      bgp_state "$batch/bgp-request" "$target" "$batch/bgp-request-state.json"
      jq -r '.pending[]' "$batch/bgp-request-state.json" > "$batch/bgp-next-request"
      mv "$batch/bgp-next-request" "$batch/bgp-request"
      remaining=$(jq '.pending|length' "$batch/bgp-state.json")
      if [ "$recovering" -eq 1 ] && [ "$remaining" -lt "$before_count" ]; then
        progress 'BGP.tools снова отвечает; полученные записи сохранены'
        recovering=0
      fi
      if [ ! -s "$batch/bgp-request" ]; then break; fi
      if [ "$timed_out" -eq 1 ] || [ "$rc" -ne 0 ]; then cycle_timeout=1; fi
    done
    if [ ! -s "$batch/bgp-request" ]; then
      wait_delay=5
      continue
    fi
    if [ "$mode" = probe ]; then return 1; fi
    if [ "$cycle_timeout" -eq 0 ]; then
      # Do not retry forever when a completed response omitted these IPs.
      cat "$batch/bgp-request" >> "$batch/bgp-unanswered"
      continue
    fi
    if [ "$remaining" -lt "$before_count" ]; then wait_delay=5; fi
    recovering=1
    progress "BGP.tools: $transport_reason; ждём $wait_delay с; недостающих IP: $remaining"
    for ((wait_left=wait_delay; wait_left>0; wait_left--)); do
      if [ "$verbose" -eq 0 ]; then progress "BGP.tools: ожидание ответа — повтор через $wait_left с"; fi
      sleep 1
    done
    wait_delay=$((wait_delay * 2)); [ "$wait_delay" -le 30 ] || wait_delay=30
  done
}

# Optional browser capture; runtime is reused, never installed for ordinary DNS mode.
if [ "$parse" -eq 1 ] && [ -z "$resume_bgp" ]; then
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
      jq -nc --arg site "$site" --arg message "$http_reason" '{site:$site, domains:[], skipped:true, errors:[$message + "; Chromium пропущен; домен будет проверен через DNS/BGP"]}' >> "$batch/skipped-pages"
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
  const workers = Math.min(20, seeds.length);
  let next = 0, completed = 0;
  let lastProgress;
  function publishProgress(i, origin, detail) {
    const status = workers > 1
      ? `обработано сайтов: ${completed}/${seeds.length}; найдено доменов: ${domains.size}`
      : `${i+1}/${seeds.length}: ${origin}; ${detail}`;
    if (status === lastProgress) return;
    fs.writeFileSync(progressPath, status);
    lastProgress = status;
  }
  async function capture(i) {
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
      if (previous && process.env.SUBNET_VERBOSE === '1') console.error(`[Этап 2/4: браузер] Редирект: ${hostname(previous.url()) || "неизвестный домен"} → ${hostname(req.url()) || "неизвестный домен"}`);
    });
    context.on('page', p => p.on('websocket', ws => record(ws.url())));
    const page = await context.newPage();
    publishProgress(i, origin, 'загрузка и прокрутка');
    let timeout, stopped = false;
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
      for(let step=0;step<10 && !stopped;step++) {
        await page.evaluate(() => window.scrollBy(0, Math.max(600, innerHeight))).catch(() => {});
        await sleep(1000);
        if (!stopped) publishProgress(i, origin, `найдено доменов: ${seen.size}`);
      }
    };
    try {
      await Promise.race([run(), new Promise((_,reject) => {timeout=setTimeout(()=>reject(new Error('capture_timeout')),45000);})]);
    } catch { errors.add('Сбор запросов не завершился за 45 секунд. Список доменов неполный.'); }
    finally { stopped = true; clearTimeout(timeout); await context.close(); }
    pages[i] = {site:origin, domains:[...seen].sort(), errors:[...errors]};
    completed++;
    if (workers > 1) publishProgress(i, origin);
    console.error(`SUBNET_PAGE_DONE ${i+1}/${seeds.length}: ${origin}; найдено доменов: ${seen.size}`);
  }
  await Promise.all(Array.from({length: workers}, async () => {
    while (next < seeds.length) await capture(next++);
  }));
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
  : > "$batch/parse-messages"
  SUBNET_VERBOSE="$verbose" node "$batch/parse.cjs" "$batch/seeds.json" "$batch/discovery.json" "$batch/parse-progress" 2> "$batch/parse-messages" &
  parse_pid=$!
  exec 4< "$batch/parse-messages"
  browser_completed_index=''
  drain_browser_messages() {
    local line completed
    while IFS= read -r line <&4; do
      case "$line" in
        SUBNET_PAGE_DONE\ *)
          completed=${line#SUBNET_PAGE_DONE }
          browser_completed_index=${completed%%:*}
          site_progress "Сбор доменов: $completed"
          finish_progress ;;
        '[Этап 2/4: браузер] Редирект:'*)
          if [ "$verbose" -eq 1 ]; then finish_progress; printf '%s\n' "$line" >&2; fi ;;
        *) finish_progress; printf '%s\n' "$line" >&2 ;;
      esac
    done
  }
  while kill -0 "$parse_pid" 2>/dev/null; do
    drain_browser_messages
    detail='запуск браузера'
    if [ -s "$batch/parse-progress" ]; then detail=$(cat "$batch/parse-progress"); fi
    if [ "${detail%%:*}" != "$browser_completed_index" ]; then progress "Сбор доменов: $detail"; fi
    sleep 1
  done
  parse_rc=0
  wait "$parse_pid" || parse_rc=$?
  parse_pid=''
  drain_browser_messages
  exec 4<&-
  [ "$parse_rc" -eq 0 ] || die 'Не удалось собрать домены сайта.' 
  else
    printf '{"domains":[],"pages":[],"complete":true}\n' > "$batch/discovery.json"
  fi
  jq --slurpfile skipped "$batch/skipped-pages" --slurpfile services "$batch/services.json" '
    .domains = ((.domains + $services[0]) | unique) |
    .pages += $skipped |
    .complete = (.complete and ($skipped|length == 0))
  ' "$batch/discovery.json" > "$batch/discovery-next.json"
  mv "$batch/discovery-next.json" "$batch/discovery.json"
  domains=()
  while IFS= read -r domain; do domains+=("$domain"); done < <(jq -r '.domains[]' "$batch/discovery.json")
  progress "Сбор завершён; уникальных доменов: ${#domains[@]}"
fi
unset inputs
stage_name='Этап 3/4: DNS'
check_bgp_service() {
  local probe_ip
  local probes=(1.1.1.1 8.8.8.8)
  if [ "$filter_ipv4" -eq 1 ]; then
    probes=(8.8.8.8 9.9.9.9)
  else
    stage_name='Подготовка DNS/BGP'
  fi
  # One route can be temporarily unavailable while WHOIS is healthy.
  for probe_ip in "${probes[@]}"; do
    printf '%s\n' "$probe_ip" > "$batch/probe-ip"
    stage="проверка BGP.tools WHOIS для $probe_ip"
    if bgp_exchange "$batch/probe-ip" "$batch/probe-bgp" probe; then return 0; fi
    if [ "$verbose" -eq 1 ]; then
      finish_progress
      jq -r '.errors[] | "[BGP.tools WHOIS] \(.ip): \(.message)"' "$batch/bgp-state.json" >&2
    fi
  done
  die "BGP.tools WHOIS: не получены пригодные префиксы и ASN для ${probes[*]}. Массовый запрос не запускается."
}
save_bgp_checkpoint() {
  local data=$checkpoint.part
  (umask 077; jq -n --slurpfile services "$batch/services.json" --slurpfile dns "$batch/dns-checkpoint.json" \
    --slurpfile discovery "$batch/discovery.json" --rawfile whois "$batch/bgp.txt" \
    --slurpfile exclusions "$batch/excluded-ips.json" \
    '{version:1,services:$services[0],dns:$dns[0],discovery:$discovery[0],whois:$whois}
     + (if $exclusions[0] == null then {} else {excluded_ipv4:$exclusions[0]} end)' > "$data") &&
    chmod 600 "$data" && mv -f "$data" "$checkpoint"
}
ipv4_index=${SUBNET_EXCLUDED_IPV4_INDEX:-}
printf 'null\n' > "$batch/excluded-ips.json"
if [ -n "$resume_bgp" ]; then
  jq -e '(.excluded_ipv4 == null) or (.excluded_ipv4 | type == "array" and all(.[]; type == "string"))' \
    "$resume_bgp" >/dev/null || die 'Файл продолжения BGP содержит некорректный список исключённых IPv4.'
  jq '.excluded_ipv4' "$resume_bgp" > "$batch/excluded-ips.json"
fi
filter_ipv4=0
if [ -n "$ipv4_index" ] || jq -e '. != null' "$batch/excluded-ips.json" >/dev/null; then filter_ipv4=1; fi
if [ -z "$resume_bgp" ]; then check_service; fi
if [ "$filter_ipv4" -eq 0 ]; then check_bgp_service; fi
stage_name='Этап 3/4: DNS'
if [ -n "$resume_bgp" ]; then
  jq '.services' "$resume_bgp" > "$batch/services.json"
  jq '.discovery' "$resume_bgp" > "$batch/discovery.json"
  if jq -e '.discovery != null' "$resume_bgp" >/dev/null; then parse=1; fi
  index=0
  observation_files=()
  for domain in "${domains[@]}"; do
    tmp="$batch/domain-$((index + 1))"
    mkdir "$tmp"
    for field in check nodes observations; do
      jq --argjson i "$index" --arg field "$field" '.dns[$i][$field]' "$resume_bgp" > "$tmp/$field.json"
    done
    observation_files+=("$tmp/observations.json")
    index=$((index + 1))
  done
else
check_dns_domain() {
  local domain=$1 index=$2 tmp=$3 http_dir=$3
  local request_id dns_started node_total answered attempt remaining pause_before
  local http_wait_seconds=0
  stage="Домен $index/${#domains[@]}: $domain — отправка задания DNS в Check-Host"
  progress "Запрашиваем DNS A для $domain..."
  if ! fetch_http check -H 'Accept: application/json' -G --data-urlencode "host=$domain" https://check-host.net/check-dns > "$tmp/check.json" ||
     ! jq -e '.ok == 1 and (.request_id | type == "string" and test("^[A-Za-z0-9]+$")) and (.nodes | type == "object" and length > 0) and (.permanent_link | type == "string" and startswith("https://check-host.net/check-report/"))' "$tmp/check.json" >/dev/null; then
    if [ "$http_transport_failed" -eq 1 ]; then check_service; fi
    jq -n --arg message "$http_reason" '{nodes:{},permanent_link:null,request_error:("Check-Host: не удалось отправить задание DNS; " + $message)}' > "$tmp/check.json"
    printf '[]\n' > "$tmp/nodes.json"
    printf '[]\n' > "$tmp/observations.json"
    return 0
  fi
  request_id=$(jq -r .request_id "$tmp/check.json")
  if [ "$verbose" -eq 1 ]; then
    printf 'Отчёт: %s\n' "$(jq -r .permanent_link "$tmp/check.json")" >&2
  fi
  printf '{}\n' > "$tmp/dns.json"
  # Bound active polling; API outage recovery pauses this budget.
  dns_started=$SECONDS
  node_total=$(jq '.nodes | length' "$tmp/check.json")
  answered=0
  for ((attempt=0; attempt<20; attempt++)); do
    remaining=$((60 - (SECONDS - dns_started)))
    [ "$remaining" -gt 0 ] || break
    stage="Домен $index/${#domains[@]}: $domain — ожидание DNS-ответов; ответили $answered/$node_total узлов; опрос $((attempt + 1))/20"
    pause_before=${http_wait_seconds:-0}
    if get_json "https://check-host.net/check-result/$request_id" > "$tmp/next.json" && jq -e 'type == "object"' "$tmp/next.json" >/dev/null; then
      dns_started=$((dns_started + ${http_wait_seconds:-0} - pause_before))
      # A non-null node response is final, including errors and empty A records.
      # Poll only for pending nodes; never replace/retry already completed ones.
      jq --slurpfile old "$tmp/dns.json" --slurpfile c "$tmp/check.json" '
        . as $next | reduce ($c[0].nodes | keys[]) as $node ($old[0];
          if .[$node] == null and $next[$node] != null then .[$node] = $next[$node] else . end)
      ' "$tmp/next.json" > "$tmp/merged.json"
      mv "$tmp/merged.json" "$tmp/dns.json"
      answered=$(jq --slurpfile c "$tmp/check.json" '. as $r | [$c[0].nodes | keys[] | select($r[.] != null)] | length' "$tmp/dns.json")
      found=$(jq '[.. | objects | .A? | arrays | .[] | strings] | unique | length' "$tmp/dns.json")
      progress "Домен $index/${#domains[@]}: $domain — ответили $answered/$node_total узлов; уникальных A-адресов: $found"
      [ "$answered" -lt "$node_total" ] || break
    else
      if [ "$http_transport_failed" -eq 1 ]; then check_service; fi
      jq --arg reason "$http_reason" '.poll_error = ($reason + "; не удалось получить отчёт Check-Host")' "$tmp/check.json" > "$tmp/check-next.json"
      mv "$tmp/check-next.json" "$tmp/check.json"
      progress 'Не удалось получить DNS-результат; переходим к следующему домену'
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
}

index=0
observation_files=()
finished=0
for domain in "${domains[@]}"; do
  index=$((index + 1))
  folder="$batch/domain-$index"
  mkdir "$folder"
  observation_files+=("$folder/observations.json")
  if [ "$dns_concurrency" -eq 1 ] || [ "${#domains[@]}" -eq 1 ]; then
    check_dns_domain "$domain" "$index" "$folder"
    continue
  fi
  while [ "$((index - 1 - finished))" -ge "$dns_concurrency" ]; do
    for slot in "${!dns_pids[@]}"; do
      pid=${dns_pids[$slot]}
      if ! kill -0 "$pid" 2>/dev/null; then
        wait "$pid" || die 'Сбой фоновой DNS-проверки.'
        unset 'dns_pids[slot]'
        finished=$((finished + 1))
      fi
    done
    if [ "$((index - 1 - finished))" -ge "$dns_concurrency" ]; then sleep 0.1; fi
  done
  (
    dns_worker=1
    trap 'exit 143' TERM
    trap 'if [ -n "$http_pid" ]; then kill "$http_pid" 2>/dev/null || :; wait "$http_pid" 2>/dev/null || :; fi' EXIT
    check_dns_domain "$domain" "$index" "$folder"
  ) &
  dns_pids[$index]=$!
  if [ "$verbose" -eq 0 ]; then progress "DNS: завершено $finished/${#domains[@]}; одновременно до $dns_concurrency"; fi
done
for slot in ${!dns_pids[@]}; do
  wait "${dns_pids[$slot]}" || die 'Сбой фоновой DNS-проверки.'
  unset 'dns_pids[slot]'
done
fi
tmp=$batch
jq -s 'add | unique' "${observation_files[@]}" > "$tmp/observations.json"
# Filter DNS observations and deduplicate across all domains before WHOIS.
if [ -n "$ipv4_index" ]; then
  jq --slurpfile index "$ipv4_index" '
    def ipnum: split(".") | map(tonumber) | reduce .[] as $octet (0; . * 256 + $octet);
    ($index[0] | to_entries | map({size:(.key | tonumber), networks:.value})) as $ranges |
    [.[].ip] | unique | map(select(
      (ipnum) as $ip | any($ranges[]; . as $range |
        (($ip / $range.size | floor) * $range.size | tostring) as $start |
        $range.networks[$start] == true)
    ))
  ' "$tmp/observations.json" > "$tmp/excluded-ips.json" || die 'Не удалось применить индекс исключённых IPv4.'
fi
jq -r --slurpfile excluded "$tmp/excluded-ips.json" \
  '([.[].ip] | unique) - ($excluded[0] // []) | .[]' "$tmp/observations.json" > "$tmp/ips"
stage_name='Этап 4/4: BGP'
if [ "$filter_ipv4" -eq 1 ]; then
  progress "Исключения ASN: пропущено IPv4 перед WHOIS — $(jq 'length' "$tmp/excluded-ips.json")"
fi
if [ -s "$tmp/ips" ]; then
  # Keep DNS data even if the process is interrupted during WHOIS.
  if [ ! -f "$batch/discovery.json" ]; then printf 'null\n' > "$batch/discovery.json"; fi
  index=0
  : > "$batch/dns-checkpoint.ndjson"
  for domain in "${domains[@]}"; do
    index=$((index + 1))
    folder="$batch/domain-$index"
    jq -nc --arg domain "$domain" --slurpfile check "$folder/check.json" \
      --slurpfile nodes "$folder/nodes.json" --slurpfile observations "$folder/observations.json" \
      '{domain:$domain,check:$check[0],nodes:$nodes[0],observations:$observations[0]}' >> "$batch/dns-checkpoint.ndjson"
  done
  jq -s . "$batch/dns-checkpoint.ndjson" > "$batch/dns-checkpoint.json"
  : > "$batch/bgp.txt"
  if [ -n "$resume_bgp" ]; then jq -r .whois "$resume_bgp" > "$batch/bgp.txt"; fi
  cache_dir="${XDG_CACHE_HOME:-$HOME/.cache}/SubnetResolve"
  mkdir -p "$cache_dir"
  checkpoint=$(mktemp "$cache_dir/bgp-resume.XXXXXXXX") || die 'Не удалось создать файл продолжения BGP.'
  save_bgp_checkpoint || die 'Не удалось сохранить DNS перед запросом BGP.tools.'
  mode=bulk
  if [ -n "$resume_bgp" ]; then mode=resume; fi
  stage="BGP-префиксы и ASN для уникальных IP: $(wc -l < "$tmp/ips" | tr -d ' ')"
  if [ "$filter_ipv4" -eq 1 ]; then check_bgp_service; fi
  if bgp_exchange "$tmp/ips" "$tmp/bgp.txt" "$mode"; then
    bgp_complete=1
  else
    finish_progress
    printf 'Не для всех IP получены BGP-префикс и ASN. Полученные записи сохранены; причины будут указаны ниже.\n' >&2
  fi
else
  : > "$tmp/bgp.txt"
fi
bgp_state "$tmp/ips" "$tmp/bgp.txt" "$tmp/final-bgp-state.json"
jq '.routes' "$tmp/final-bgp-state.json" > "$tmp/routes.json"
jq '.errors' "$tmp/final-bgp-state.json" > "$tmp/bgp-errors.json"
index=0
full_files=()
for domain in "${domains[@]}"; do
  index=$((index + 1))
  tmp="$batch/domain-$index"
jq -n --arg domain "$domain" --argjson verbose "$verbose" \
  --slurpfile c "$tmp/check.json" --slurpfile n "$tmp/nodes.json" \
  --slurpfile x "$batch/excluded-ips.json" --slurpfile o "$tmp/observations.json" --slurpfile b "$batch/routes.json" --slurpfile be "$batch/bgp-errors.json" '
  # Reject unrelated/malformed ranges, including a prefix not containing its IP.
  def ipnum: split(".") | map(tonumber) | if length == 4 and all(.[]; . >= 0 and . <= 255) then reduce .[] as $v (0; . * 256 + $v) else error("Invalid IPv4") end;
  [$b[0][] | . as $route | select(any($o[0][]; .ip == $route.ip)) |
   (.prefix | split("/")) as $p | pow(2; 32 - ($p[1]|tonumber)) as $size |
   select(try (((.ip|ipnum) / $size | floor) == (($p[0]|ipnum) / $size) ) catch false)] as $routes |
  [$o[0][] | . as $obs | $routes[] | select(.ip == $obs.ip) | . + {node: $obs.node}] as $joined |
  ([$o[0][].ip] | unique) as $observed |
  ($observed - ($x[0] // [])) as $queried |
  {domain: $domain, record_type: "A",
   results: ($joined | group_by([.asn, .prefix]) | map(
     . as $group | .[0] | {asn, as_name, prefix, country, registry, allocated} +
     {ips: ([$group[].ip] | unique), check_host: ([$group[].node] | unique),
      resolutions: ($group | group_by(.ip) | map({ip: .[0].ip, check_host: ([.[].node] | unique)}))} +
     (if $verbose == 1 then {check_host_details: ([$group[].node] | unique | map(. as $node | {key: $node, value: $c[0].nodes[$node]}) | from_entries)} else {} end))),
   errors: ((if $c[0].request_error then [{error: "Не удалось запустить DNS-проверку", message: $c[0].request_error}] else [] end) +
     (if $c[0].poll_error then [{error: "Не удалось получить DNS-отчёт", message: $c[0].poll_error}] else [] end) +
     [$n[0][] | select(.ips | length == 0) |
       . as $n | ($c[0].nodes[.node]) as $details |
       ([.response | .. | objects | (.message?, .error?) | strings] | unique) as $messages |
       {check_host: .node, country: $details[1], city: $details[2],
        error: (if .response == null then "Узел не предоставил DNS-результат"
                elif ($messages | join(" ") | test("timeout|timed out"; "i")) then "Узел сообщил о превышении времени ожидания"
                elif ($messages | length > 0) then "Узел сообщил об ошибке DNS" else "Узел ответил без IPv4-адресов" end),
        message: (if .response == null then ($c[0].poll_error // "Узел не предоставил результат до завершения опроса")
                  elif ($messages | length > 0) then ($messages | join("; "))
                  else "Узел ответил, но не вернул IPv4 A-записи" end), response: .response}] +
     ($queried | map(. as $ip | select(all($routes[]; .ip != $ip)) | ([$be[0][] | select(.ip==$ip)] | first // {ip:$ip,error:"Не получены BGP-префикс и ASN",message:"BGP.tools не прислал данные для этого IP"})))),
   permanent_link: $c[0].permanent_link} |
  . + {complete: (($observed | length > 0) and all(.errors[]; .check_host != null))} +
  (if $x[0] == null then {} else {excluded_ips: ($observed - $queried)} end)
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
  printf 'Для части доменов или IP не удалось получить DNS/BGP-данные:\n' >&2
  jq -r '.domains[] | .domain as $d |
    (if (.results | length == 0) and all(.errors[]; .check_host != null) then
       "[\($d)] Check-Host: ни один узел не вернул IPv4 A-запись."
     else empty end),
    (.errors[] | select(.check_host == null) |
     "[\($d)] \(.ip // "Check-Host"): \(.error)" +
     (if .message != null and .message != .error then " — \(.message)" else "" end))' "$tmp/batch.json" >&2
fi
if [ "$verbose" -eq 1 ] && jq -e 'any(.domains[].errors[]; .check_host != null)' "$tmp/batch.json" >/dev/null; then
  finish_progress
  jq -r '.domains[] | .domain as $d | .errors[] | select(.check_host != null) |
    "[\($d)] \(.check_host) [\(.country // "—"), \(.city // "—")]: \(.error)" +
    (if .message != null and .message != .error then " — \(.message)" else "" end)' "$tmp/batch.json" >&2
  jq -c '.domains[] | .domain as $d | .errors[] | {domain: $d} + .' "$tmp/batch.json" >&2
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
if [ "$rules" -eq 1 ]; then
  if [ -n "${SUBNET_BGP_OBSERVATIONS:-}" ]; then
    jq '[.domains[].results[] | {asn, as_name, prefix}] | unique' "$batch/batch.json" > "$SUBNET_BGP_OBSERVATIONS"
  fi
  if [ "$parse" -eq 1 ]; then
    cp "$batch/discovery.json" "$batch/rule-discovery.json"
  else
    printf '{"pages":[]}\n' > "$batch/rule-discovery.json"
  fi
  jq -n --slurpfile services "$batch/services.json" --slurpfile data "$batch/batch.json" --slurpfile discovery "$batch/rule-discovery.json" '
    {rules: [$services[0][] as $service |
      ([$service] + [$discovery[0].pages[] | select(.site==$service) | .domains[]] | unique) as $hosts |
      {ruleTag:$service, domain: ($hosts | map("domain:" + .)), ip: ([$data[0].domains[] | . as $d | select($hosts | index($d.domain)) | .results[].prefix] | unique | sort)}]}
  ' > "$tmp/output.json"
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
