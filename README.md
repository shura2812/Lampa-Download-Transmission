# Lampa-Download-Transmission
Это модификация агента https://github.com/apk-storage/lampa-downloader-agent.git сделанная с помощью ИИ.
Оригинальный агент сам запускает qBittorrent-клиент и скачивает файл.
Эта модификация позволяет отправлять magnet-ссылку на файл выбранный в Lampa отдельно стоящему Transmission серверу.
Для работы нужно добавить в Lampa оригинальный плагин (https://apk-storage.github.io/lampa-plugins/plugin.js).

Компилировать можно в Windows.
Скопировать на машину с Armbian можно при помощи scp из powershell.
Для установки на Armbain нужно запустить installagent.sh
Если все прошло без ошибок, выполнить пункты 4 и 5 пошагово вручную.

После запуска агента как сервиса по необходимости запускаем:
/opt/lampa-agent/agent -code             # показывает код для подключения (спаривания) устройства (ПК, смартфон, ТВ). Это придется сделать хотя бы один раз.
/opt/lampa-agent/agent -pair             # запускает режим спаривания
/opt/lampa-agent/agent -status           # JSON snapshot - пока не работает
/opt/lampa-agent/agent -quit             # clean shutdown (Restart=on-failure won't restart on clean exit)
