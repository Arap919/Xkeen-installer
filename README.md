# XKeen Installer

Графический мастер установки XKeen, Mihomo/Xray, router-watchdog и XKeen UI PWA на подготовленный Keenetic.

## Подготовка роутера

Нужны заранее подготовленный Entware, SSH с POSIX shell и доступ к `/opt`. Настройки KeeneticOS, форматирование накопителя, выбор OPKG, DNS, политики клиентов и перезагрузка выполняются вручную. Если Entware отсутствует, мастер останавливается и предлагает ручную подготовку с повторной проверкой. SMB-передача и автоматическая установка Entware пока не подтверждены.

Последовательность работы: подготовка → подключение → проверка → ядра → компоненты → конфигурация → просмотр и подтверждение плана → установка → проверка результата. Конфликты конфигурации требуют ручного согласования. До записи создаётся проверяемая закрытая резервная копия. Отмена сохраняет выполненные изменения; повтор требует новой проверки и подтверждения нового плана.

Пароли и подписки не сохраняются в browser storage или отчётах. Первый ключ SSH подтверждается отдельно и хранится в памяти до закрытия приложения; неожиданная замена блокируется. Ключ локального CA остаётся в закрытом хранилище компьютера. Установка доверия CA требует отдельного подтверждения; на других устройствах доверие настраивается вручную.

## Сборка

Зафиксированы Wails 2.17.1, Go 1.26.3 и Node.js 26.5.0 с npm. Нужны системные зависимости [Wails v2](https://v2.wails.io/docs/gettingstarted/installation/). WebView берётся из системы:

| Цель | Среда сборки и запуска | Результат |
| --- | --- | --- |
| Windows amd64 | Windows 10/11, установленный WebView2 Runtime | `xkeen-installer.exe` в ZIP |
| macOS amd64/arm64 | macOS 12+, Xcode Command Line Tools для сборки, системный WKWebView | `xkeen-installer.app` в ZIP |
| Linux amd64 | Ubuntu 24.04; GTK 3 и WebKitGTK 4.1, для сборки также gcc/pkg-config и development packages | `xkeen-installer` в tar.gz |

Минимум macOS 12 учитывает [требования Go 1.26](https://go.dev/wiki/MinimumRequirements); работа на старых версиях macOS не проверена. Linux-архив зависит от системных библиотек Ubuntu 24.04 и не является универсальным пакетом для всех дистрибутивов.

Из корня проекта:

```sh
cd frontend
npm ci
npm run typecheck
npm test
npm run build
cd ..
go test ./...
go vet ./...
go run github.com/wailsapp/wails/v2/cmd/wails@v2.17.1 build
```

На Linux установите `build-essential pkg-config libgtk-3-dev libwebkit2gtk-4.1-dev`; добавляйте `-tags webkit2_41` к Go test/vet и Wails build. На Windows используйте `build -platform windows/amd64 -webview2 error`: приложение требует установленный WebView2 и не загружает его автоматически. На macOS для минимума 12 задайте `CGO_CFLAGS=-mmacosx-version-min=12.0` и `CGO_LDFLAGS=-mmacosx-version-min=12.0` перед сборкой.

На macOS результат находится в `build/bin/xkeen-installer.app`. Режим разработки: `go run github.com/wailsapp/wails/v2/cmd/wails@v2.17.1 dev`.

## Что проверено

На компьютере: тесты Go, vet, frontend typecheck/тесты/production build и нативная сборка macOS arm64. Сценарии установки проверяются через fixtures, а SSH/SFTP и HTTPS — локальными тестовыми серверами. Команды, соответствие сценариям и ограничения перечислены в [docs/testing.md](docs/testing.md).

В CI: запусков нет. Файл `.github/workflows/build.yml` подготовлен локально для четырёх целей и имеет только ручной запуск. Публикация workflow, его запуск, push и релиз не выполнялись. Успех сборки macOS arm64 не подтверждает Windows, macOS amd64 или Linux.

На реальном роутере: установка, сетевые политики, запуск ядер, watchdog, HTTPS/PWA и повтор после обрыва не проверены. Системное доверие CA также не устанавливалось. Fixtures не подтверждают работу пакетов и служб на устройстве.

Архивы предназначены для проверки, без установщиков ОС, подписи для распространения и notarization. Wails может выполнять локальную ad hoc подпись macOS. Реальный deploy, системное доверие, публикация и подпись требуют отдельных действий пользователя.
