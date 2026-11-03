# План реализации XKeen Installer

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans or superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Цель:** графический установщик Entware, выбранных ядер XKeen, router-watchdog и XKeen UI PWA с сохранением существующих настроек.

**Архитектура:** Go управляет SSH, передачей файлов, проверками и последовательностью операций. Wails связывает его с TypeScript-мастером. Чтение состояния и подготовка плана отделены от записи; frontend не выполняет shell-команды.

**Стек:** Go, Wails, TypeScript, SSH/SFTP, SMB при подтверждённой совместимости; встроенные YAML/JSON-шаблоны.

**Дизайн:** `docs/superpowers/specs/2026-11-04-xkeen-installer-design.md`.

## Общие ограничения

- Отдельный проект `/Users/olegfirskov/xkeen-installer`; не менять UI/watchdog и не создавать worktree.
- Русские UI/README/планы; английские код, комментарии и технические документы.
- Настройки KeeneticOS вручную; никакого скрытого форматирования, переключения OPKG или reboot.
- Сохранять конфигурации; резервная копия до записи; несовместимость слияния блокирует соответствующий этап.
- Xray/Mihomo/оба; watchdog активируется только при активном совместимом Mihomo.
- Никаких секретов в Git, журнале или localStorage; CA key не передавать на роутер.
- Реальную установку, push и публикацию не выполнять без отдельного разрешения.

## Основные риски для проверки

1. Обрыв SSH после применения команды: повтор сначала читает состояние и не предполагает, что команда не выполнялась.
2. Существующий YAML с anchors/custom listeners: не разрушать формат и не терять ключи при дополнении.
3. Подмена SSH host key или смена адреса: блокировать неожиданное изменение, не принимать автоматически.
4. Нехватка места или неудачная backup: никаких дальнейших мутаций.
5. Остановка между установкой пакета и активацией: честный частичный результат, возможность перепроверки.

---

### Задача 1: Проверить интерфейсы поставщиков и bootstrap Entware

**Файлы:** `docs/technical/install-contracts.md`, `internal/catalog/catalog.go`, `internal/catalog/catalog_test.go`.

**Интерфейсы:** `Resolve(component Component, arch RouterArch) (Artifact, error)` возвращает проверенный источник, версию, архитектуру и доступную проверку целостности; никаких мутаций роутера.

- [ ] Проверить официальные release assets, XKeen autoinstall, структуру Entware tar.gz, UI init/data paths, watchdog feed и cron contracts. Записать точные ссылки и ограничения.
- [ ] Проверить три архитектуры, отказ неизвестной архитектуры и несоответствие metadata в тестах каталога; сначала увидеть провал `go test ./internal/catalog`.
- [ ] Реализовать каталог, разрешение конкретных версий и верификацию артефактов. Не объявлять SHA-проверку там, где upstream не публикует digest.
- [ ] Проверить SMB bootstrap на локальном тестовом ресурсе и архиве, без пользовательского роутера; отдельно документировать, какое ручное действие запускает распаковку. Если SMB не подтверждён, оставить явный ручной fallback вместо имитации успеха.
- [ ] Запустить тесты каталога; зафиксировать контракт как основу следующих задач.

### Задача 2: Транспорт, обнаружение и резервная копия

**Файлы:** `internal/router/{transport,ssh,inspect,backup}.go` и соответствующие `_test.go`.

**Интерфейсы:** `Transport.Run(ctx, command) (Result, error)`, `Transport.Read(ctx, path)`, `Transport.WriteAtomic(ctx, path, data, mode)`; `Inspect(ctx, Transport) (Snapshot, error)`; `Backup(ctx, Transport, Snapshot) (BackupManifest, error)`.

- [ ] Написать тесты first-use/changed SSH key, таймаута, не shell Entware, ARM64/MIPS/MIPSel, неизвестного CPU, существующих конфигов и альтернативного cron init.
- [ ] Убедиться в провале тестов; реализовать SSH с context, проверкой ключей и безопасной передачей данных без интерполяции секретов в команды.
- [ ] Написать тесты сохранения прав, неполной backup и нехватки места: при ошибке write/активация не вызываются.
- [ ] Реализовать приватную backup и manifest; повторно прочитать результат перед допуском мутаций.
- [ ] Проверить `go test ./internal/router` на fake transport и локальном SSH fixture.

### Задача 3: Конфигурации обоих ядер и watchdog

**Файлы:** `internal/config/{templates,merge,validate}.go`, `internal/config/templates/*`, `internal/config/*_test.go`.

**Интерфейсы:** `Prepare(snapshot Snapshot, selection Selection, input Import) (ConfigProposal, error)` возвращает новые файлы, patches, редактированный preview и конфликты без записи.

- [ ] Написать fixtures для новой установки, существующего Xray, Mihomo anchors, пользовательских групп/listeners, пустой подписки и конфликтующего порта.
- [ ] Проверить провал тестов; встроить минимальные согласованные шаблоны Xray/Mihomo и параметры watchdog.
- [ ] Реализовать импорт с ограничением размера и редактирование preview без секретов. Существующий конфиг без изменений возвращается побайтно неизменным.
- [ ] Для неоднозначного YAML не выполнять автоматическую сериализацию всего файла: вернуть конфликт и точное необходимое дополнение.
- [ ] Проверить тестами, что Xray active не запускает watchdog, а оба ядра сохраняют выбранное active. Проверить конфиги доступными валидаторами ядер в изолированной среде.

### Задача 4: Планирование и выполнение установки

**Файлы:** `internal/install/{plan,runner,state,components}.go`, `internal/install/*_test.go`.

**Интерфейсы:** `BuildPlan(snapshot Snapshot, selection Selection, proposal ConfigProposal) (Plan, error)`; `Run(ctx, plan Plan, transport Transport, emit func(Event)) (Report, error)`.

- [ ] Написать тесты порядка backup→install→validate→activate, отказа исполнения устаревшего плана, отмены, обрыва SSH после мутации и повторного запуска.
- [ ] Реализовать последовательные шаги с перепроверкой состояния. Фиксировать реально завершённые изменения и не обещать rollback opkg.
- [ ] Использовать upstream noninteractive XKeen contract, штатный IPK watchdog и сохраняющий данные adapter UI вместо интерактивного uninstall/setup.sh.
- [ ] Проверять контрольные суммы по доступному контракту, права файлов и версии. Не обновлять все пакеты Entware без включения этого действия в показанный план.
- [ ] Проверить `go test ./internal/install` на изолированных fake-router сценариях clean/existing/both/cancel/retry.

### Задача 5: HTTPS и проверка служб

**Файлы:** `internal/tls/{authority,certificate,trust}.go`, `internal/verify/services.go`, соответствующие тесты.

**Интерфейсы:** `PrepareTLS(address string, existing TLSState) (TLSProposal, error)`; `Verify(ctx, Transport, Plan) (VerificationReport, error)`.

- [ ] Написать тесты SAN IP/DNS, срока/назначения сертификата, сохранения существующего TLS и запрета CA key в payload.
- [ ] Реализовать генерацию Go crypto/x509, закрытое локальное хранение и явное платформенное действие доверия; при отказе показать незавершённое доверие без падения установки служб.
- [ ] Проверять процесс, конфигурацию и API отдельно: открытый TCP-порт не является доказательством исправности.
- [ ] Прогнать `go test ./internal/tls ./internal/verify`; подтвердить redaction диагностик.

### Задача 6: Графический мастер

**Файлы:** `main.go`, `app.go`, `wails.json`, `frontend/src/*`, `frontend/package.json`, `frontend/*config*`.

**Интерфейсы Go→UI:** `Inspect`, `PreparePlan`, `StartInstall`, `CancelInstall`, `ExportRedactedReport`; события `install:progress` содержат step/status/message без секретов.

- [ ] Прочитать frontend-design перед созданием экранов. Собрать русский мастер из девяти шагов с тремя вариантами ядер и пояснением watchdog.
- [ ] Написать тесты переходов: только актуальная инспекция допускает план; только подтверждённый план допускает запись; повторный клик не запускает второй runner.
- [ ] Реализовать Go bridge, progress/cancel, конфликт конфигураций, просмотр изменений и финальный частичный/успешный результат.
- [ ] Не хранить credentials в browser storage; очистить поля по завершении сессии. Host key подтверждается отдельным диалогом.
- [ ] Проверить frontend typecheck/build и UI сценарии с fake backend; запустить desktop на macOS и проверить визуально.

### Задача 7: Упаковка и итоговая проверка

**Файлы:** `README.md`, `docs/testing.md`, `.github/workflows/build.yml`, конфигурация упаковки Wails.

- [ ] Подготовить сборки Windows amd64, macOS amd64/arm64 и Linux amd64 с учётом системного WebView. CI подготовить локально без публикации workflow/релизов.
- [ ] Выполнить `go test ./...`, `go vet ./...`, frontend typecheck/tests/build, доступную desktop сборку.
- [ ] Проверить всю цепочку с fixtures: clean Entware, missing Entware/manual fallback, existing custom configs, Xray only, Mihomo only, both, no space, network failure, cancel/retry.
- [ ] Выполнить независимое ревью перед заявлением готовности; исправить находки в пределах утверждённого дизайна.
- [ ] В README разделить проверенное на компьютере, проверенное в CI и ещё не проверенное на реальном роутере. Реальный deploy и публикация остаются отдельными действиями пользователя.
