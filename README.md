# subproxy

Проксирование подписок VPN.

## Как использовать

Сначала добавить профиль `/whoami`, после чего посмотреть содержимое json, скопировать значение поля `serverDescription`. После чего добавить профиль `/{host}/{path}/{скопированное_значение}`.

Полученным конфигом можно манипулировать при помощи скрипта, закодированного через URL-safe base64, который используется в проекте. Для запуска скрипта нужно указать его в самом конце `/{host}/{path}/{скопированное_значение}/{script}`. Заголовки передаются как объект. Если тело ответа целиком является JSON, первым аргументом будет разобранное значение, иначе строка.

```js
export const handle = async (response_body, response_headers) => {
  return { body: String(response_body), headers: response_headers };
};
```

## Сборка

```powershell
cargo zigbuild --target x86_64-unknown-linux-musl --release
```

## Развертывание

```/etc/angie/sites-enabled/subproxy
server {
    listen 80;
    server_name <domain>;

    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }

    location / {
        return 301 https://$host:443$request_uri;
    }
}

server {
    listen 443 ssl;
    listen 443 quic reuseport;
    http2 on;

    server_name <domain>;

    ssl_certificate /etc/letsencrypt/live/<domain>/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/<domain>/privkey.pem;

    add_header Alt-Svc 'h3=":443"; ma=86400;' always;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;

    location / {
        proxy_pass         http://127.0.0.1:8080;
        proxy_http_version 1.1;

        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host  $host;
        proxy_set_header X-Forwarded-Port  $server_port;
        proxy_set_header Connection        "";

        proxy_read_timeout 86400;
        proxy_send_timeout 86400;
    }
}
```

```/etc/systemd/system/subproxy.service
[Unit]
Description=Subproxy Service
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=/root/subproxy

User=root
Group=root

Restart=always
RestartSec=3
LimitNOFILE=65535

WorkingDirectory=/root

[Install]
WantedBy=multi-user.target
```