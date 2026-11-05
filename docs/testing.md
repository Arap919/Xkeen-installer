# Проверка XKeen Installer

## Границы результатов

Локально проверяются Go-код, frontend, системная сборка macOS arm64 и сценарии с подменённым транспортом. В этих сценариях работают настоящие inspector, подготовка конфигурации, planner и runner; загрузка проверенных артефактов и удалённая файловая система заменены fixtures. Команды ядер моделируются: тест не запускает ARM/MIPS бинарники на компьютере.

SSH/SFTP-тесты используют локальный SSH-сервер; API/HTTPS-тесты — локальные HTTP/TLS-серверы. Frontend использует jsdom и fake backend. Это отдельные границы проверки, а не один полный прогон GUI → SSH → загрузка релизов → роутер.

На Windows выполняются SSH host-key/SFTP/cancellation и общие TLS-тесты. Только fixtures, которым нужны локальный POSIX shell и Unix-права, пропускаются; проверки приватности TLS используют Windows DACL, включая отказ при доступе Everyone. Symlink-подтест пропускается лишь при отсутствии соответствующего права Windows. Эти Windows-проверки подготовлены и скомпилированы локально; выполнение на Windows ещё не подтверждено.

## Локальные команды

Среда: Go 1.26.3, Node.js 26.5.0, Wails 2.17.1, macOS arm64.

```sh
cd frontend
npm ci
npm run typecheck
npm test
npm run build
cd ..
go test ./...
go vet ./...
go test ./internal/install -run TestFixture -v
CGO_CFLAGS=-mmacosx-version-min=12.0 CGO_LDFLAGS=-mmacosx-version-min=12.0 go run github.com/wailsapp/wails/v2/cmd/wails@v2.17.1 build -platform darwin/arm64 -trimpath
```

Эти проверки выполняются перед итоговым заявлением о локальной сборке. Точный вывод текущего прогона сохранён в `.superpowers/sdd/2026-11-04-xkeen-installer/task-7-validation.log`.

Генератор Wails может добавлять завершающие пробелы в `frontend/wailsjs/go/models.ts`; после сборки нормализуйте только пробелы в концах строк и пустые строки в конце файла, сохранив одну финальную новую строку. Для проверки всего изменения учитывайте также новые файлы; обычный unstaged `git diff --check` их не проверяет.

## Сценарии fixtures

| Сценарий | Проверка | Что подтверждает |
| --- | --- | --- |
| Чистый Entware, Xray only | `TestFixtureCleanEntwareCoreMatrix/xray` | Импорт → план → подтверждение → backup → установка → validation → activation |
| Чистый Entware, Mihomo only | `TestFixtureCleanEntwareCoreMatrix/mihomo` | Provider import и та же цепочка, точные байты конфигурации |
| Entware отсутствует | `TestFixtureManualEntwareAndNoSpaceGates/missing-entware` | Ручная подготовка, отказ плана, отсутствие записи и команд установки |
| Существующая custom-конфигурация | `TestFixtureCustomMihomoPreservesAnchorsListenersAndBackup` | Anchors, listeners, комментарии и права сохранены в рабочем файле и backup |
| Оба ядра | `TestCleanBothWithInactiveXrayAndActiveMihomo` | Активен Mihomo, Xray сохранён как неактивный с честным pending |
| Нет места до плана / место исчезло | `TestFixtureManualEntwareAndNoSpaceGates` | Отказ до записи, пакеты и службы не изменены |
| Ошибка загрузки / backup | `TestDownloadFailureAndBackupFailureStopMutations` | Нет продолжения установки после отказа |
| Обрыв после записи / повтор | `TestDisconnectAndRetryRequiresFreshPlan` | Частичный результат, старый план одноразовый, новая проверка позволяет повтор |
| Отмена до записи / после установки / после start | `TestStaleAndCancellationDoNotMutate`, `TestCleanXrayAndCancellationAfterInstall`, `TestCancellationAfterStartIsUncertainWithoutRollbackClaim` | Завершённые записи остаются, неопределённость обозначена; автоматический откат не заявлен |
| Watchdog | `TestWatchdogIPKAfterNativeActivationAndPreservesExactConfig`, `TestExistingWatchdogScheduleBlocksXrayBeforeMutation` | Только совместимый активный Mihomo, IPK после native validation, настройки сохранены |
| HTTPS UI | `TestNewUIWithTLSAndBackupGate`, `TestExistingValidTLSPreservedExactlyAndNoKeyPreview` | Backup/TLS gates, сохранение существующих сертификатов |
| Фактическая проверка результата | `TestVerifySeparatesProcessConfigAPIHTTPSAndTrust`, `TestControllerFromBackendConfigAndMeaningfulVersion` | Разделены процесс, конфиг, API, HTTPS и доверие; невалидный API не принимается |
| Мастер и повторная проверка | `TestDoubleStartAndCancelRequireReinspection`, `frontend/src/wizard.test.ts` | Один runner, явное подтверждение, отмена требует новой проверки, итоговый экран сохраняет partial result |

## Подготовленная CI-матрица

`.github/workflows/build.yml` имеет только `workflow_dispatch`, read-only доступ к содержимому и закреплённые SHA официальных actions. Go/Node/Wails закреплены. Подготовлены Windows amd64 (`windows-2022`), macOS amd64 (`macos-15-intel`), macOS arm64 (`macos-15`) и Linux amd64 (`ubuntu-24.04`).

Каждая задача устанавливает зависимости, проверяет frontend и Go, собирает Wails и архивирует результат. Windows требует установленный WebView2; Linux использует `webkit2_41` с GTK3; macOS использует системный WKWebView. Архив сохраняет структуру приложения/исполняемые права. Upload сохраняет только архив сборки, не создаёт релиз. Наличие такого файла не означает успешную проверку CI: workflow не опубликован и не запускался.

Параметры сверены с [Wails v2 CLI](https://v2.wails.io/docs/reference/cli/), [зависимостями Wails v2](https://v2.wails.io/docs/gettingstarted/installation/) и [официальными образами runner](https://github.com/actions/runner-images). Требования Go 1.26 выше старого минимального macOS из документации Wails.

## Что ещё требует отдельной проверки

Реальный ARM64/MIPSel/MIPS роутер: подготовка OPKG/Entware, shell/SFTP fallback, скачивание и исполнение конкретных релизов, резервная копия на накопителе, сохранение маршрутизации, API Mihomo, cron watchdog и HTTPS/PWA. Нужны также реальные обрыв SSH, переподключение и повтор, подтверждение неизменности пользовательских настроек, восстановление из backup вручную при необходимости.

Windows/macOS amd64/Linux: фактический CI build, распаковка и запуск на каждой системе, WebView и системные зависимости. Доверие CA на каждой ОС и других устройствах, подпись для распространения, notarization и релиз не выполнялись.

Перед реальной установкой пользователь отдельно подтверждает конкретный план в мастере. Разработка и локальные fixtures не дают такого подтверждения.
