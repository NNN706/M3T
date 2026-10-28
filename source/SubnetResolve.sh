#!/usr/bin/env bash
set -euo pipefail

verbose=0

while getopts ":v" opt; do
  case "$opt" in
    v) verbose=1 ;;
    *) printf 'Usage: %s [-v] [domain]\n' "$0" >&2; exit 1 ;;
  esac
done

shift $((OPTIND - 1))

domain="${1:-samokat.ru}"

if (( $# > 1 )); then
  printf 'Usage: %s [-v] [domain]\n' "$0" >&2
  exit 1
fi

# Check-Host API

printf 'Получаем узлы Check-Host для %s...\n' "$domain" >&2

check_host_response=$(
  curl -fsSG \
    --connect-timeout 5 \
    --max-time 20 \
    -H "Accept: application/json" \
    --data-urlencode "host=$domain" \
    'https://check-host.net/check-dns'
)

jq -e '
  .ok == 1
  and (.nodes | type == "object" and length > 0)
  and (.permanent_link | type == "string")
' <<< "$check_host_response" > /dev/null

mapfile -t ips < <(
  jq -r '.nodes | to_entries[].value[3]' <<< "$check_host_response"
)

total=${#ips[@]}

printf '[0/%d] IP получены. Запрашиваем BGP.tools...\n' "$total" >&2

# BGP.tools Bulk WHOIS

bgp_response=$(
  {
    printf 'begin\n'
    printf '%s\n' "${ips[@]}"
    printf 'end\n'
  } | nc -w 20 bgp.tools 43
)

printf '[%d/%d] Ответ получен. Формируем JSON...\n' "$total" "$total" >&2

# JSON

jq -n \
  --argjson check "$check_host_response" \
  --arg raw "$bgp_response" \
  --argjson verbose "$verbose" '
  
  (
    $raw
    | split("\n")
    | map(
        select(length > 0)
        | split("|")
        | map(gsub("^\\s+|\\s+$"; ""))
      )
    | map(
        select(
          length >= 7
          and (.[1] | test("^([0-9]{1,3}\\.){3}[0-9]{1,3}$"))
        )
      )
    | map({
        key: .[1],
        value: {
          prefix: .[2],
          asn: ("AS" + .[0]),
          as_name: .[6],
          country: .[3],
          registry: .[4],
          allocated: .[5]
        }
      })
    | from_entries
  ) as $bgp

  | {
      results: (
        $check.nodes
        | to_entries
        | to_entries
        | map(
            .key as $index
            | .value.key as $node
            | .value.value as $details
            | $details[3] as $ip
            | $bgp[$ip] as $route

            | if $route == null then
                error("BGP result missing for " + $ip)
              else
                {
                  id: ($index + 1),
                  ip: $ip,
                  prefix: $route.prefix,
                  asn: $route.asn,
                  as_name: $route.as_name,
                  country: $route.country,
                  registry: $route.registry,
                  allocated: $route.allocated,
                  check_host: $node
                }
                +
                (
                  if $verbose == 1 then
                    {
                      check_host_details: {
                        ($node): $details
                      }
                    }
                  else
                    {}
                  end
                )
              end
          )
      ),

      permanent_link: $check.permanent_link
    }
' > results.json

received=$(jq '.results | length' results.json)

printf 'Готово: %d/%d. Результаты сохранены в results.json\n' \
  "$received" "$total" >&2

jq . results.json