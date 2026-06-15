# На VPS Ваш домен (усл. yourdomain.com) используется всего в 3 местах и в 6 строках:
1) Файл server.json: <br>
30 строка:   ("**yourdomain.com**" // Replace with your domain)<br>

2) Файл nginx.conf:  <br>
12 строка:   server_name yourdomain.com;<br>
14 строка:   ssl_certificate "/etc/letsencrypt/live/**yourdomain.com**/fullchain.pem";<br>
15 строка:   ssl_certificate_key "/etc/letsencrypt/live/**yourdomain.com**/privkey.pem";<br>
16 строка:   ssl_trusted_certificate "/etc/letsencrypt/live/**yourdomain.com**/chain.pem";<br>

3) Команда для выдачи сертификатов: <br>
certbot certonly --standalone -d **yourdomain.com** --non-interactive --agree-tos -m admin@example.com <br>

# В панели Remnawave Ваш домен используется в двух местах:
![При добавлении ноды (можно заменить на IP ноды)](../../source/images/AddNode.png)
![При добавлении хоста](../../source/images/AddHost.png)

# Базовая терминология для дальнейшей успешной работы:
Протокол (Protocol): VLESS, Trojan, Hysteria - это то, что вы вводите в "protocol": "...",
- Имеет свои настройки, обычно на следующей строке: "settings": {"...", "..."}

Транспорт (Transport Methods): RAW (бывш. TCP), XHTTP, Hysteia, - это то, что вы вводите в "network": "...",
- Определяет, как именно переносится поток данных, например через RAW, WebSocket, gRPC, Hysteria и другие.
- Имеет свои настройки  "rawSettings": {"...", "..."} (в нашем примере пустой),
                        "xhttpSettings": {"...", "..."},
                        "kcpSettings": {"...", "..."},
                        "grpcSettings": {"...", "..."},
                        "wsSettings": {"...", "..."},
                        "httpupgradeSettings": {"...", "..."},
                        "hysteriaSettings": {"...", "..."}

Безопасность транспорта (Transport Security): TLS, Reality - это то, что вы вводите в "security": "...",
- Определяет механизм защиты, например TLS или REALITY.
- Имеет свои настройки: "realitySettings": {"...", "..."} (Выбор в нашем примере),
                        "tlsSettings": {"...", "..."}

Эти три группы относятся к разным уровням и в определенных пределах могут комбинироваться

