# Совместимость проверки MIPS с BusyBox Entware

Пользователь подтвердил: uname mips, BusyBox od отвергает -A, opkg работает. SFTP-сервер отсутствует, но существующий transport уже поддерживает безопасный shell fallback; устанавливать SFTP для проверки не требуется. Предложенный дополнительный этап отменён до интеграции.

- [x] Заменить определение MIPS endian на dd с чтением шести байтов ELF и поддерживаемый BusyBox od -b.
- [x] Проверить ELF32/ELF64, оба порядка байтов, octal offsets и отказы для некорректных/лишних/неполных данных.
- [x] Проверить полный router suite, существующий SFTP-less fallback, ревью и сборку macOS ARM64/ZIP.

Настройки роутера и пользовательские конфигурации не меняются. Новых зависимостей и действий записи при проверке не добавляется.

Проверено: go test -race ./internal/router -count=1 прошёл, включая SFTP-less round trip и verified backup, матрицу MIPS ELF и отказы. Независимое статическое ревью без блокеров. Сборка Wails darwin/arm64/typecheck/production build прошла. Новые SFTP-модули/поля/GUI-тесты полностью убраны; существующий shell fallback сохранён. Проверка на физическом роутере при разработке не выполнялась.

## BusyBox stat compatibility

- [x] Replace GNU stat -c with BusyBox stat -t for metadata and wc -c for atomic-upload size checks.
- [x] Preserve symlink guards, exact path parsing, file type validation and permissions.
- [x] Add stat-t-only SSH fixtures and malformed metadata regression tests.
- [x] Verify router race suite and independent review; rebuild macOS ARM64 and verify both embedded core templates.

Validation: go test -race ./internal/router -count=1 passed. Full go test ./... rerun was denied; no full-suite success claimed for this stage. Native Wails build passed. Physical-router validation remains pending.
