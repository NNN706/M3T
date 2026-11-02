# Проверка RU Direct в Xray

Workflow **Xray RU Direct deployment and browser test** работает в `test` при изменениях шаблона, списка сайтов или тестового сценария. Доступен ручной запуск. `main` не меняется.

- Конфиг берётся из `Templates/Routing-(RU-Direct)/routing-ru.json`, включая DNS и порядок правил. Генерируемые `source/routing/IP.json` и `domains.json` этим сценарием не подключаются.
- Тестовый конфиг сохраняет `direct`, заменяет `proxy` на `block` и использует `block` по умолчанию. Внутренние DNS-запросы направляются через `direct` отдельным правилом по `inboundTag`.
- Xray запускается на тестовом сервере в Docker, Chromium — на Admiralteskiy через SSH → SOCKS5. SOCKS опубликован только на loopback сервера. QUIC отключён; прямого обхода прокси нет.
- Очередь: `source/routing/sites.txt` и обязательные URL из `required-sites.json`, без повторов. До 10 сайтов одновременно, один проход, до 60 секунд на открытие интерфейса, затем 10 секунд JavaScript/прокрутки. Никакой авторизации.

## Настройка

На тестовом сервере нужны Docker с Compose plugin и SSH-пользователь с правом запускать Docker. Порт `127.0.0.1:10808` должен быть свободен. Используется только Compose project/container `m3t-xray-routing-test`, файлы — `~/m3t-xray-routing-test/releases/<sha>-<run>/`. Квоты CPU/RAM не задаются. Мониторинг настраивается отдельно владельцем сервера.

Пока `XRAY_HOST` не задан, локальные CI-тесты выполняются, живой деплой явно пропускается. При заданном host остальные параметры обязательны.

В GitHub Environment **xray-routing-test**:

| Тип | Имя | Значение |
|---|---|---|
| Variable | `XRAY_HOST` | DNS-имя или IPv4 тестового сервера |
| Variable | `XRAY_USER` | SSH-пользователь |
| Variable | `XRAY_SSH_PORT` | SSH-порт, по умолчанию 22 |
| Variable | `XRAY_IMAGE` | `ghcr.io/xtls/xray-core:VERSION@sha256:DIGEST` |
| Secret | `XRAY_SSH_KEY` | Отдельный SSH-ключ CI |
| Secret | `XRAY_KNOWN_HOSTS` | Проверенная запись known_hosts сервера, для нестандартного порта — `[host]:port` |

Образ публикуется официальным [workflow XTLS/Xray-core](https://github.com/XTLS/Xray-core/blob/main/.github/workflows/docker.yml). Версию выбирает владелец стенда; получить digest: `docker buildx imagetools inspect ghcr.io/xtls/xray-core:VERSION`. Workflow принимает только официальный registry/repository с версией и SHA256; `latest` без digest не принимается. Проверки TLS-сертификатов и SSH host key включены.

## Обязательные сайты

Редактируйте **`source/xray-test/required-sites.json`**:

```json
{"url":"https://example.ru/login","text":"Войти|Личный кабинет","selector":"input:not([type=hidden]), button"}
```

`text` — регулярное выражение, `selector` — CSS-селектор видимого элемента. Для успеха нужны конечный HTTP 2xx, непустой интерфейс, ожидаемый текст и элемент, отсутствие видимой капчи/страницы защиты. Это эвристика публичного интерфейса, не проверка авторизации или всех функций сайта. Профили могут требовать уточнения при изменении дизайна сайтов; первый живой запуск проверяет их пригодность.

Отказы обычных сайтов и ресурсов CDN/API — статистика. Отказ обязательного сайта делает CI красным **после завершения всей очереди**. Конфиг остаётся на сервере для анализа. Ошибка `xray run -test` не заменяет предыдущий контейнер. Проверка default block требует записи решения Xray в логе; одного тайм-аута curl недостаточно. Деплои выполняются последовательно.

Artifacts содержат `sites.json`, таблицу, снимки неоткрывшихся страниц, конфиг и логи Xray. SHA, digest, имя контейнера и время позволяют сопоставить запуск с Grafana. Измеряется весь Xray с DNS/соединениями, а не отдельно память matcher. Бюджеты RAM/CPU не определяют статус CI.

Локальная проверка: `cd source/xray-test && npm ci && npx playwright install --only-shell chromium && npm test`. На Linux системные зависимости Chromium должны быть установлены администратором раннера заранее; workflow не вызывает интерактивный sudo.
