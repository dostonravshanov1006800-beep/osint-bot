# OSINT Bot + Mini App

Telegram-бот (@Global_mrkt_bot) и Mini App для разведки по **публичным** данным:

- 🔍 Ник — на каких соцсетях зарегистрирован username (GitHub, Telegram, Reddit, GitLab, Steam, YouTube, TikTok)
- 🌐 Домен — регистратор, даты, DNS (RDAP + dns.google)
- 📡 IP — страна, город, провайдер (ipwho.is → ipinfo.io)
- 🕳 Email — базы утечек (Have I Been Pwned, нужен ключ HIBP_API_KEY)

## Деплой на Deno Deploy (бесплатно)

1. Зайдите на https://dash.deno.com → Sign in with GitHub
2. New Project → выберите этот репозиторий → Deploy
3. Settings → Environment Variables → добавьте:
   - `OSINT_BOT_TOKEN` — токен бота (из @BotFather → /mybots → @Global_mrkt_bot → API Token)
   - `HIBP_API_KEY` — (опционально) ключ с haveibeenpwned.com
4. После деплоя получите URL вида `https://xxx.deno.dev`

## Подключение Telegram

Установите webhook (замените URL на ваш):

```
https://api.telegram.org/bot<ТОКЕН>/setWebhook?url=https://xxx.deno.dev/hook?secret=osint_hook_7f3k9x&allowed_updates=["message","callback_query"]
```

Mini App: `https://xxx.deno.dev/` — можно повесить на меню-кнопку бота.

## Эндпоинты

| Путь | Назначение |
|---|---|
| `GET /` | Mini App (HTML) |
| `POST /api` | JSON API `{action: nick\|domain\|ip\|email, query}` |
| `POST /hook?secret=osint_hook_7f3k9x` | Telegram webhook |

Сессии хранятся в Deno KV (встроенная база Deno Deploy). Никаких платных сервисов.
