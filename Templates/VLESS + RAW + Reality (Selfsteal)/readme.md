# Базовая настройка протокола VLESS с конфигурацией транспорта RAW + Reality
---
### 1. Аренда зарубежного VPS
---
### 2. Домен
Существует два способа завладеть своим собственным доменом     
- Способ 1 - В сервисах регистрации, у хостеров. После регистрации рекомендую делегировать домен на ns-сервера Cloudflare или на другие популярные сервисы (предпочтительно)  
- Способ 2 - Взять бесплатно в [FreeDNS](https://freedns.afraid.org/) или [DuckDNS](https://www.duckdns.org)  
Далее необходимо всего одно действие: добавить A-запись домена, а затем и поддомена (node.yourserver.com) на IP вашего VPS
Итогом правильных действий этого пункта будет отображение вашего айпи в сервисе [nslookup](https://www.nslookup.io)

---
### 3. Сертификат
Далее выполнение действий будет происходить на нашей VPS     
Необходимо выпустить сертификат, для вашего сайта, который будет отдавать Reality нечистям, кто сканирует вас     
```bash
certbot certonly --standalone -d yourdomain.com --non-interactive --agree-tos -m admin@example.com
```
Итогом правильного выполнения действий этого пункта будет отображение вашего домена в директории с сертификатами:     
```bash
ls /etc/letsencrypt/live
```

---
### 4. nginx.conf (создание)
Создадим файл nginx.conf в директории remnanode
```bash
cat > /opt/remnanode/nginx.conf <<'EOF'
server_names_hash_bucket_size 64;

map \$http_upgrade \$connection_upgrade {
    default upgrade;
    ""      close;
}

ssl_protocols TLSv1.2 TLSv1.3;
ssl_ecdh_curve X25519:prime256v1:secp384r1;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305;
ssl_prefer_server_ciphers on;
ssl_session_timeout 1d;
ssl_session_cache shared:MozSSL:10m;
ssl_session_tickets off;
server {
    server_name yourdomain.com;
    listen unix:/dev/shm/nginx.sock ssl proxy_protocol;
    http2 on;

    ssl_certificate "/etc/letsencrypt/live/yourdomain.com/fullchain.pem";
    ssl_certificate_key "/etc/letsencrypt/live/yourdomain.com/privkey.pem";
    ssl_trusted_certificate "/etc/letsencrypt/live/yourdomain.com/chain.pem";

    root /var/www/html;
    index index.html index.htm;

    add_header X-Robots-Tag "noindex, nofollow, noarchive, nosnippet, noimageindex" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Referrer-Policy "no-referrer" always;

    location / {
        try_files \$uri \$uri/ =404;
  }
}

server {
    listen unix:/dev/shm/nginx.sock ssl proxy_protocol default_server;
    server_name _;
    add_header X-Robots-Tag "noindex, nofollow, noarchive, nosnippet, noimageindex" always;
    ssl_reject_handshake on;
    return 444;
}
EOF
echo "✅ Конфигурация nginx создана!"
```
Итогом правильных действий этого пункта будет отображение четырех строк при вызове команды:     
```bash
# Замените yourdomain.com на ваш домен
cat /opt/remnanode/nginx.conf | grep "yourdomain.com"
```

---
### 5. docker-compose.yml
```bash
cat > /opt/remnanode/docker-compose.yml <<'EOF'
x-logging: &logging
  logging:
    driver: json-file
    options:
      max-size: 100m
      max-file: 5

x-common: &common
  ulimits:
    nofile:
      soft: 1048576
      hard: 1048576
  restart: always

services:
  remnanode-nginx:
    image: nginx:1.28
    container_name: remnawave-nginx
    hostname: remnawave-nginx
    <<: [*common, *logging]
    network_mode: host
    volumes:
      - /opt/remnanode/nginx.conf:/etc/nginx/conf.d/default.conf:ro
      - /dev/shm:/dev/shm:rw
      - /var/www/html:/var/www/html:ro
      - /etc/letsencrypt/:/etc/letsencrypt:ro
    command: sh -c 'rm -f /dev/shm/nginx.sock && exec nginx -g "daemon off;"'

  remnanode:
    container_name: remnanode
    hostname: remnanode
    image: remnawave/node:latest
    cap_add:
      - NET_ADMIN
    <<: [*common, *logging]
    volumes:
      - /etc/letsencrypt:/etc/letsencrypt
      - '/var/log/remnanode:/var/log/remnanode'
      - ./geosite.dat:/usr/local/share/xray/roscomgeosite.dat:ro
      - ./geoip.dat:/usr/local/share/xray/roscomgeoip.dat:ro
      - /dev/shm:/dev/shm:rw
    environment:
      - NODE_PORT=2222
      - SECRET_KEY="Your Secret Key"
EOF
echo "✅ Docker Compose файл создан!"
```

---
### По итогу на VPS ваш домен (усл. yourdomain.com) используется всего в 3 местах и в 6 строках:
1) Файл **server.json**:      
30 строка:   ("**yourdomain.com**" // Replace with your domain)     

2) Файл **nginx.conf**:       
12 строка:   server_name **yourdomain.com**;     
14 строка:   ssl_certificate "/etc/letsencrypt/live/**yourdomain.com**/fullchain.pem";     
15 строка:   ssl_certificate_key "/etc/letsencrypt/live/**yourdomain.com**/privkey.pem";     
16 строка:   ssl_trusted_certificate "/etc/letsencrypt/live/**yourdomain.com**/chain.pem";     

3) Команда для выдачи сертификатов:      
```bash
certbot certonly --standalone -d yourdomain.com --non-interactive --agree-tos -m admin@example.com      
```
---
### В панели Remnawave ваш домен используется в двух местах:
При добавлении ноды (можно заменить на IP ноды)     
При добавлении хоста     
![При добавлении ноды (можно заменить на IP ноды)](../../source/images/AddNode.png)
![При добавлении хоста](../../source/images/AddHost.png)

---
### Базовая терминология для дальнейшей успешной работы:
Протокол (Protocol): VLESS, Trojan, Hysteria - это то, что вы вводите в **"protocol": " "**,     
- Имеет свои настройки:      "settings": {   }     

Транспорт (Transport Methods): RAW (бывш. TCP), XHTTP, Hystiria, - это то, что вы вводите в **"network": " "**,     
- Определяет, как именно переносится поток данных, например через RAW, WebSocket, gRPC, Hysteria и другие.     
- Имеет свои настройки       - "rawSettings": {   } (в нашем примере пустой),     
                        - "xhttpSettings": {   },     
                        - "kcpSettings": {   },     
                        - "grpcSettings": {   },     
                        - "wsSettings": {   },     
                        - "httpupgradeSettings": {   },     
                        - "hysteriaSettings": {   }     

Безопасность транспорта (Transport Security): TLS, Reality - это то, что вы вводите в **"security": " "**,     
- Определяет механизм защиты, например TLS или REALITY.     
- Имеет свои настройки:      - "realitySettings": {   } (Выбор в нашем примере),     
                        - "tlsSettings": {   }     

Эти три группы относятся к разным уровням и в определенных пределах могут комбинироваться     

