### При сопоставлении inboundTag к outboundTag важно, чтобы параметры подключения соответствовали друг другу
#### Пример:<br>
Входящее подключение, к которому изначально подключается наш "хост" (клиент, или сервисный пользователь: см. https://docs.rw/learn/server-routing)<br>
```json
    {
      "tag": "RUSPB_VLESS_INBOUND",
      "port": 443,
      "protocol": "vless",
      "settings": {
        "flow": "xtls-rprx-vision",
        "clients": [],
        "decryption": "none"
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls",
          "quic"
        ]
      },
      "streamSettings": {
        "network": "raw",
        "security": "reality",
        "realitySettings": {
          "xver": 1,
          "target": "/dev/shm/nginx.sock",
          "spiderX": "",
          "shortIds": [
            ""
          ],
          "privateKey": "Генерация через docker exec -it remnanode xray x25519 или в окне редактирования "Config Profiles",
          "fingerprint": "randomized",
          "serverNames": [
            "yourdomain.com"
          ]
        }
      }
    },
```
<br>
Исходящее подключения, которое переадресует нас к входящему:<br>

```json
    {
      "tag": "RUSPB_VLESS_OUTBOUND",
      "protocol": "vless",
      "settings": {
        "id": "User, имеющий доступ к этому inbound, можно специально создать в панели remnawave и привязать к соотвествующему inboundTag", // https://docs.rw/learn/server-routing
        "flow": "xtls-rprx-vision-udp443",
        "port": 443,
        "address":   "yourdomain.com",
        "encryption": "none"
      },
      "streamSettings": {
        "network": "raw",
        "security": "reality",
        "realitySettings": {
          "password": "Генерация через docker exec -it remnanode xray x25519 -i <ключ из inboundTag, строка 31> или в окне редактирования "Config Profiles",
          "serverName": "yourdomain.com",
          "fingerprint": "randomized"
        }
      }
    }
```