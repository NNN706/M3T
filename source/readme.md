# SubnetResolve

Запуск с GitHub (Bash):

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/NNN706/M3T/main/source/SubnetResolve.sh)
```

Прогресс обновляется одной строкой в терминале; `-v` включает подробный журнал. JSON — в stdout, прогресс и ссылка отчёта — в stderr.

Введите домен. Сохранение в `resolved.json` — по запросу, по умолчанию **нет**.

Только уникальные IPv4-подсети, без сохранения:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/NNN706/M3T/main/source/SubnetResolve.sh) -4s example.com
```

Флаги: `-v` — подробный журнал и полные данные узлов; `-4` — только подсети; `-s` — без вопроса и сохранения.

Для загрузки нужны Bash и curl; остальные зависимости устанавливаются автоматически через доступный пакетный менеджер.
