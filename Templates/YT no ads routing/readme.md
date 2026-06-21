# YouTube without ADS rotuing
#### Если скрипт проверки локации определил RU на YouTube:
```bash
bash <(wget -qO- https://ipregion.vrnt.xyz)
```
#### Или с русской ноды тест блокировок показал доступ к YouTube:
```bash
bash wget -qO- censorcheck.tlab.pw | bash  <br>
```
#### То воспользуемся этим для скрытия рекламы
Для этого нам необходимо пустить YouTube в ноду, в которой нет рекламы<br>
Важно понимать, что метод не устраняет рекламу с ноды, на которой она изначально есть, она лишь пересылает подключение на ноду, где рекламы нет<br>
### При сопоставлении inboundTag к outboundTag важно, чтобы параметры подключения соответствовали друг другу
#### Пример:<br>
Входящее подключение, к которому изначально подключается наш клиент, или сервисный пользователь: см. https://docs.rw/learn/server-routing<br>
```json
    {
      "tag": "RU_VLESS_INBOUND",
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
          "privateKey": "Генерация через docker exec -it remnanode xray x25519 или в окне редактирования "Config Profiles" - Generate Keypair",
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
      "tag": "RU_VLESS_OUTBOUND",
      "protocol": "vless",
      "settings": {
        "id": "User, имеющий доступ к этому inbound, можно специально создать в панели remnawave и привязать к соотвествующему inboundTag", // https://docs.rw/learn/server-routing
        "flow": "xtls-rprx-vision-udp443",
        "port": 443,
        "address": "yourdomain.com",
        "encryption": "none"
      },
      "streamSettings": {
        "network": "raw",
        "security": "reality",
        "realitySettings": {
          "password": "Генерация через docker exec -it remnanode xray x25519 -i <ключ из inboundTag, строка 31> или в окне редактирования "Config Profiles"- Generate Keypair",
          "serverName": "yourdomain.com",
          "fingerprint": "randomized"
        }
      }
    }
```
### Обязательно изучите и закиньте в нейросеть как базу для дальнейшей помощи:
https://xtls.github.io/ru/config/routing.html - основы Routing<br>
https://xtls.github.io/ru/config/inbounds/vless.html - конфигурация протокола Vless для входящего подлючения<br>
https://xtls.github.io/ru/config/outbounds/vless.html - конфигурация протокола Vless для исходящего подлючения<br>
https://xtls.github.io/ru/config/routing.html#balancerobject - необязательный параметр!<br>