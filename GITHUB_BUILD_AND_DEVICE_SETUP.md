# Сборка TweakForce через GitHub Actions и установка напрямую на iPhone

В репозиторий добавлен полноценный CI/CD workflow (`.github/workflows/build.yml`), который собирает готовые `.deb`-пакеты для **RootHide** и **Rootless** (архитектура `arm64e`, iOS 15.0–18.x) на облачных раннерах macOS. 

Вам больше не нужен Mac или локальный Theos — вся сборка происходит в облаке GitHub, а результат скачивается и устанавливается прямо на телефон.

---

### Шаг 1. Выгрузка проекта в ваш GitHub

1. Создайте новый пустой репозиторий на [GitHub](https://github.com/new), например `TweakForce` (Private или Public).
2. В терминале проекта выполните команды для привязки и отправки кода:
   ```bash
   git remote add origin https://github.com/<ВАШ_НИКНЕЙМ>/TweakForce.git
   git branch -M main
   git push -u origin main
   ```
3. *(Опционально)* Если вы хотите, чтобы GitHub сразу создал релиз с готовыми прямыми ссылками на `.deb`:
   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   ```

---

### Шаг 2. Автоматическая сборка в GitHub Actions

1. Перейдите во вкладку **Actions** в вашем репозитории на GitHub.
2. Вы увидите запущенный workflow **Build TweakForce (.deb)**.
3. Workflow автоматически:
   - Разворачивает раннер `macos-14` с Apple Clang.
   - Клонирует Theos с поддержкой RootHide и пропатченные iOS SDK.
   - Компилирует компоненты с аппаратными PAC-флагами arm64e (`-fptrauth-calls`, `-fptrauth-returns`, `-fptrauth-intrinsics`).
   - Собирает как отдельные `.deb` пакеты, так и объединенный пакет **All-In-One Suite** (`com.tweakforce.suite_1.0.0_roothide_iphoneos-arm64e.deb`).
   - Загружает артефакты сборки.

---

### Шаг 3. Скачивание и установка прямо на iPhone 11 Pro Max

1. **Скачивание на устройстве:**
   - Откройте Safari на вашем iPhone.
   - Перейдите в ваш репозиторий на GitHub.
   - Если вы создавали тег (`v1.0.0`): откройте раздел **Releases** и нажмите на файл `.deb`.
   - Если собиралось по обычному коммиту: откройте вкладку **Actions** -> выберите последний запуск -> внизу в секции **Artifacts** скачайте `tweakforce-roothide-debs` (Safari скачает zip-архив).
2. **Установка пакета:**
   - **Через Filza File Manager:** откройте скачанный файл (или распакуйте zip), нажмите на `com.tweakforce.suite_1.0.0_roothide_iphoneos-arm64e.deb` -> выберите **Установить** (Install) в правом верхнем углу.
   - **Через Sileo / Zebra:** при открытии `.deb` в Safari выберите «Поделиться» -> «Открыть в Sileo» -> Установить.
   - **Через Терминал (NewTerm / SSH на телефоне):**
     ```bash
     dpkg -i /var/mobile/Downloads/com.tweakforce.suite_*.deb
     ```
3. Скрипт `postinst` пакета автоматически:
   - Создаст каталоги конфигурации `/var/jb/etc` и логов `/var/jb/var/mobile/Library/Logs/TweakForce/`.
   - Установит и зарегистрирует LaunchDaemon через `launchctl bootstrap`.

---

### Шаг 4. Настройка спуфинга на телефоне

1. **Конфигурационный файл:**
   - Находится по пути `/var/jb/etc/tweakforce.json`.
   - Вы можете открыть и редактировать его прямо на телефоне в Filza (встроенный текстовый редактор).
   - Пример настройки для AIDA64:
     ```json
     "com.finalwire.aida64": {
       "injection": true,
       "hiding": false,
       "dylibs": [
         "/var/jb/usr/lib/TweakForce/libTweakForceHooks.dylib"
       ],
       "values": {
         "device_name_override": "TweakForce-iPhone",
         "device_model_override": "iPhone15,3",
         "system_version_override": "18.0"
       }
     }
     ```
2. **RootHide Bootstrap:**
   - Откройте приложение RootHide на iPhone.
   - В разделе **App List** убедитесь, что целевое приложение включено (чтобы Loader разрешал внедрение dylib).
3. **Crane (Контейнеризация):**
   - Откройте Crane в Настройках -> целевое приложение.
   - Создайте **новый контейнер** с включенной опцией изоляции Keychain.
4. **Запуск и проверка:**
   - Запустите AIDA64 из созданного контейнера Crane.
   - Проверьте вкладки **Device** и **System**: модель устройства отобразится как заданная в конфиге (`iPhone 14 Pro Max` / `iPhone15,3`), а версия iOS — как `18.0`.
   - Просмотр логов в реальном времени (в Filza или NewTerm):
     ```bash
     tail -f /var/jb/var/mobile/Library/Logs/TweakForce/daemon.log
     ```

---

### Статус реализации и честные технические оговорки

- **Статус кода:** Проект является инженерным прототипом с реализацией PAC-обхода для arm64e и хуков перехвата sysctl/UIDevice. До успешной компиляции на GitHub Actions и запуска на физическом устройстве код не считается подтверждённым.
- **Диагностика компиляции:** Если GitHub Actions при первой сборке завершится с ошибкой (например, из-за специфических версий SDK или строгости Clang), лог компилятора в GitHub Actions покажет точную строку и причину, что позволит быстро внести точечные исправления.
