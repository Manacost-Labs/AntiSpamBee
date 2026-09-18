# AntiSpamBee

AntiSpamBee — Telegram-бот модерации рекламы и спама. Он анализирует сообщения,
bio, личный канал пользователя и публичные реакции, сохраняет объяснимые сигналы
и выполняет действия через надёжную очередь.

## Что уже работает

- защищённый Telegram webhook с ограничением размера и secret token;
- NATS JetStream с durable consumer и дедупликацией по Telegram `update_id`;
- PostgreSQL-события, detector signals, решения, действия и audit log;
- реклама работы, adult/порно, VPN, казино, крипты, займов и обычные промо;
- скрытые `text_link`, URL и базовая нормализация обфускации;
- анализ bio, username, личного канала и его последних публикаций;
- проверка профиля пользователя, поставившего реакцию;
- flood, повторяющиеся сообщения и история предыдущих нарушений;
- OpenRouter `~typesafe/jev-latest` в безопасном shadow-режиме;
- allowlist, пользовательские жалобы и Telegram-команды модераторов;
- идемпотентный Action Worker с lease, retry, `retry_after`, reconciliation и DLQ.

## Политика действий

```text
risk < 0.90       → ALLOW
risk 0.90–0.999…  → DELETE_MESSAGE или DELETE_REACTION
risk = 1.00       → BAN_USER
```

Автоматическое действие дополнительно требует confidence `>= 0.90`, evidence
coverage `>= 0.50`, разрешённую policy и непривилегированного пользователя.
Администраторы, владелец и allowlist никогда не банятся автоматически. Ошибка
проверки статуса пользователя приводит к review, а не к действию.

Jev остаётся shadow-detector: его результат хранится, но самостоятельно не
удаляет сообщения и не банит пользователей.

Поток выполнения:

```text
Telegram → Gateway → JetStream → Detectors → Decision Engine
                                      ↓
PostgreSQL ← signals + decision + queued action
                                      ↓
                            Action Worker → Telegram
```

## Telegram-интерфейс

- `/start`, `/help` — подробный справочник и кнопка «Добавить в группу»;
- `/report` — пожаловаться, отправив команду ответом на сообщение;
- `/status` — текущий режим защиты;
- `/protection observe|soft|standard|strict` — изменить режим;
- `/allow`, `/unallow` — управление allowlist ответом на сообщение;
- `/warn`, `/mute`, `/ban` — действие модератора ответом на сообщение;
- `/unban USER_ID` — снять блокировку по Telegram ID.

Кнопка добавления открывает системный выбор группы Telegram и запрашивает только
права удаления сообщений и ограничения участников. После подтверждённого
успешного бана бот публикует в защищаемой группе уведомление с Telegram ID
заблокированного пользователя.

Административные команды проверяют статус вызывающего пользователя через
`getChatMember`. `/ban` и `/mute` попадают в Action Worker, а не вызывают
разрушительный Telegram API напрямую.

Режимы: `OBSERVE` и `SOFT` оставляют решение модератору, `STANDARD` разрешает
удаление без автобана, `STRICT` включает удаление и бан при risk `1.00`.

Для удаления сообщений и реакций боту необходимо право
`can_delete_messages`, для ban/mute — `can_restrict_members`. Webhook должен
включать `message_reaction`; setup-команда делает это автоматически.

## Локальный запуск

Требования: Go 1.23+, Docker и Docker Compose.

```bash
docker compose up -d
cp .env.example .env
# Заполните Telegram-параметры. OPENROUTER_API_KEY можно оставить пустым.
set -a
. ./.env
set +a
```

Запустите три процесса:

```bash
go run ./cmd/gateway
go run ./cmd/moderation-worker
go run ./cmd/action-worker
```

После публикации HTTPS endpoint зарегистрируйте webhook:

```bash
go run ./cmd/setup-webhook
```

Health endpoints:

- gateway: `:8080/healthz`, `:8080/readyz`;
- action worker: `:8081/healthz`, `:8081/readyz`;
- moderation worker: `:8082/healthz`, `:8082/readyz`, `:8082/metrics`.

## Production Compose

Задайте настоящий `POSTGRES_PASSWORD` и секреты в `.env`, затем:

```bash
docker compose -f compose.prod.yml up -d --build
```

Сервис `migrate` применяет ещё не выполненные SQL-миграции до запуска workers.
Не храните `.env` в Git. Если API-ключ когда-либо публиковался в чате или Git,
его необходимо отозвать и создать новый.

## Проверка

```bash
go test -race ./...
go vet ./...
go build ./cmd/gateway
go build ./cmd/moderation-worker
go build ./cmd/action-worker
go build ./cmd/setup-webhook
```

CI поднимает PostgreSQL, применяет миграции, запускает integration tests, race
detector, vet и сборку всех команд.

## Ограничения текущего MVP

- реклама, существующая только внутри картинки или аватара, пока не проходит OCR;
- анонимную реакцию `actor_chat` нельзя связать с конкретным пользователем;
- Jev нельзя переводить из shadow без размеченного golden set и проверки false positives;
- production backup/restore и внешний маршрут апелляции настраиваются отдельно.
