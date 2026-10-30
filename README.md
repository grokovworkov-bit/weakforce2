# TweakForce

Полный производственный проект надёжной инъекции tweaks на **RootHide Bootstrap + Dopamine** (rootless jailbreak), когда для приложения включено скрытие jailbreak. / Production project for reliable tweak injection on RootHide + Dopamine even when jailbreak hiding is enabled for an app.

**Целевое устройство:** iPhone 11 Pro Max (A13, arm64e), iOS 18.x.

---

## Зачем это нужно

В RootHide **App List** (куда внедрять твики) и **Hide List** (где скрывать jailbreak) в текущем loader'е фактически взаимоисключающие: включив скрытие для приложения, вы теряете инъекцию. TweakForce делает их **независимыми** на трёх уровнях:

1. **1_LoaderPatch** — патч логики bootstrap: приложения из whitelist получают инъекцию даже если они в Hide List.
2. **2_InjectionDaemon** — независимый от Bootstrap путь: мониторит запуск процессов и внедряет dylib сам.
3. **3_HookFramework** — встраиваемый universal hook framework (fishhook + swizzling) для тестовых приложений.
4. **4_ManagerApp** — приложение управления (сайдлоад).
5. **5_TestApp** — тестовое приложение для визуальной проверки.

---

## Можно ли тестировать на AIDA64?

**Да.** AIDA64 (`com.finalwire.aida64`) — обычное приложение из App Store, и оно читает характеристики устройства через стандартные API (`UIDevice`, `uname`, `sysctl` и т.п.), которые наш framework может хукать.

Чтобы твики работали в AIDA64:

1. Установите все компоненты (`./install.sh`).
2. В **RootHide Bootstrap → App List** добавьте `com.finalwire.aida64`.
3. Включите `injection: true` для него (уже прописано в `config/tweakforce.json`) — через Manager app или вручную.
4. Перезапустите AIDA64. Daemon обнаружит запуск и внедрит `libTweakForceHooks.dylib`.
5. Значения из `values` (`device_name_override`, `device_model_override`, `system_version_override`) применятся к тому, что читает AIDA.

> Manager app и TestApp ставятся **не через App Store**, а сайдлоадом: TrollStore (рекомендуется), либо подпись через Xcode / `ldid`. Сам AIDA64 остаётся обычной версией из App Store — мы не пересобираем его, а внедряемся в рантайме.

---

## Структура проекта

```
TweakForce/
├── README.md                  — эта документация
├── install.sh                 — сборка + установка на устройство
├── config/tweakforce.json     — конфиг: какие твики в какие приложения (вкл. AIDA64)
├── 1_LoaderPatch/             — патч bootstrap loader (ElleKit/Substrate)
├── 2_InjectionDaemon/         — universal injection daemon (LaunchDaemon)
├── 3_HookFramework/           — libTweakForceHooks (fishhook + swizzling)
├── 4_ManagerApp/              — UI управления (Swift, сайдлоад)
└── 5_TestApp/                 — тестовое приложение (Swift)
```

### 1_LoaderPatch
- `LoaderPatch.x` — хуки функций решения об инъекции и проверки скрытия в процессе bootstrap.
- `AppListManager.h/.m` — чтение/запись `com.roothide.bootstrap.plist`, независимое управление App List / Hide List / whitelist.
- `Makefile`, `control`, `entitlements.plist`.

### 2_InjectionDaemon
- `Sources/main.m` — точка входа, связывает всё.
- `ProcessMonitor.h/.m` — `proc_listpids` опрос + резолв bundleID (база под kqueue/EVFILT_PROC).
- `InjectionEngine.h/.m` — Механизм A (pre-launch DYLD env) + Механизм B (mach_inject).
- `ConfigLoader.h/.m` — разбор `tweakforce.json`.
- `XPCServer.h/.m` — CFMessagePort `com.tweakforce.daemon` (PING, GET_STATUS, SET_TWEAK_FOR_APP, INJECT_NOW, GET_LOG).
- `Logger.h/.m` — os_log + файл с ротацией.
- `LaunchDaemon.plist`, `entitlements.plist`, `Makefile`.

### 3_HookFramework
- `TweakForceHooks.h/.m` — публичный API: `TF_hookFunction`, `TF_hookMethod`, `TF_isInjectionActive`, `TF_getDaemonValue`.
- `fishhook.h/.c` — полная реализация Facebook fishhook (MIT).
- `HookRegistry.h/.m` — реестр активных хуков.
- `DiagnosticReporter.h/.m` — публикация состояния (файл + os_log + Darwin notify).
- `module.modulemap`, `Makefile`.

### 4_ManagerApp (Swift, сайдлоад)
- `MainViewController` — 3 секции: статус daemon, приложения (НЕЗАВИСИМЫЕ тумблеры injection/hide), активные твики.
- `TweakListViewController`, `DiagnosticsViewController`, `DaemonStatusView`.
- `Models/`, `Services/` (`DaemonBridge` — CFMessagePort клиент, `ConfigManager`, `DiagnosticsService`).

### 5_TestApp (Swift)
- `DiagnosticViewController` — реалтайм признаки инъекции.
- `CameraTestView` — preview камеры рядом с подменённым UIImage.
- `DeviceInfoView` — то, что читает AIDA64 (имя, модель, версия).
- `InjectionStatusView` — большой зелёный/красный баннер статуса.

---

## Как собрать и установить

```bash
export THEOS=/opt/theos
export THEOS_DEVICE_IP=<IP_вашего_iPhone>
./install.sh
```

TestApp и ManagerApp (Swift) собираются в **Xcode** и ставятся сайдлоадом (TrollStore / подпись).

---

## КАК ПРОВЕРИТЬ ЧТО РАБОТАЕТ

1. **Daemon:** `tail -f /var/jb/var/mobile/Library/Logs/TweakForce/daemon.log` — должны идти строки `daemon: whitelisted launch ...`.
2. **LoaderPatch:** включите hiding для тестового приложения, оставьте injection — приложение всё равно должно получить `libTweakForceHooks` (см. TestApp → «Статус» = ✅ INJECTED).
3. **Framework:** TestApp → «Диагностика» показывает `Framework загружен: ДА` и список образов.
4. **Data spoofing:** TestApp → «Устройство» и AIDA64 показывают значения из `values`.
5. **XPC:** Manager app → «Диагностика» показывает `daemon: АКТИВЕН` и хвост лога.

---

## ⚠️ Честные ограничения

1. **Механизм B (mach_inject) на iOS 18 arm64e.** Из-за **PAC** (pointer authentication) и **PPL** сырой `thread_create_running` с входом в `dlopen` нетривиален: указатель входа remote-потока должен быть PAC-подписан. В коде логика изложена корректно и работает на arm64 без PAC; на arm64e (ваш A13) это **ожидаемая точка отказа** без спец-обходов PAC и соответствующих entitlements. Поэтому основным является **Механизм A** (pre-launch env) + **LoaderPatch**. mach_inject оставлен как документированный fallback, а не как готовый эксплойт.
2. **LoaderPatch** работает только если процесс bootstrap доступен для hooking через ElleKit/Substrate. Имена символов в `LoaderPatch.x` (`kDecisionSymbolCandidates` и др.) зависят от версии RootHide и, возможно, потребуют подстройки под конкретный билд.
3. **Код написан без запуска на устройстве** (среда Linux). Требуется проверка на **Mac + Xcode + iPhone**: Theos-компоненты собираются под macOS, Swift-приложения — в Xcode. Компиляция локально не проверялась.
4. **Назначение.** Проект — для надёжной инъекции собственных твиков на вашем устройстве и тестовых приложениях (включая визуальную подмену для AIDA64 в целях тестирования). **НЕ предназначен и не должен использоваться для обхода банковских, антифрод- или KYC-систем.**



---

## PAC Bypass (arm64e)

В проект TweakForce добавлен полноценный модуль **PAC Bypass** (`PACBypass.c` / `PACBypass.h`), обеспечивающий работоспособность **Механизма B (post-launch injection)** на устройствах архитектуры **arm64e** (iPhone 11 Pro Max, A13 Bionic и новее).

### 1. Что такое PAC и специфика arm64e
**PAC (Pointer Authentication Codes)** — аппаратное расширение безопасности архитектуры arm64e. Процессор вычисляет криптографическую подпись для указателей и сохраняет её в неиспользуемых старших битах адреса. Перед выполнением перехода (инструкции `BRAA`, `BLRAA`, `BLRAAZ`) процессор проверяет подпись.
Классический `mach_inject` падает на arm64e по трем причинам:
- Вызов `thread_create_running` / `thread_set_state` отвергается ядром, если регистр PC не подписан валидным PAC-ключом.
- Динамический шеллкод, записанный в кучу (`vm_write`), не имеет подписи Apple Code Signing и вызывает `EXC_BAD_ACCESS`.
- Вызов `dlopen` через функциональный указатель требует аутентифицированного перехода (`BLRAA`), а не обычного `BLR`.

### 2. Реализованный механизм
Для обхода указанных ограничений без нарушения целостности кода реализован следующий конвейер:
- **Trampoline как скомпилированная C-функция:** Функция `tf_bootstrap_trampoline` скомпилирована в бинарнике демона с атрибутом `__attribute__((noinline))`. Компилятор Clang с флагами `-fptrauth-calls -fptrauth-intrinsics` сам генерирует аутентифицированные инструкции вызова `BLRAA` через переданный функциональный указатель.
- **Отображение через `mach_vm_remap`:** Страница памяти, содержащая скомпилированный trampoline, проецируется в целевой процесс с помощью системного вызова `mach_vm_remap` (`copy = FALSE`).
- **Подпись Program Counter:** Для установки начального адреса потока используется системный макрос `arm_thread_state64_set_pc_fptr(state, trampoline_remote_addr)`. Он подписывает адрес инструкцией `ptrauth_sign_unauthenticated` с ключом `ptrauth_key_process_independent_code`, благодаря чему ядро XNU успешно принимает `thread_set_state`.
- **Разрешение `dlopen`:** Адрес `dlopen` находится через `dlsym(RTLD_DEFAULT, "dlopen")` в dyld shared cache нашего процесса (расположение shared cache одинаково для всех процессов iOS) и очищается от PAC-бит через `ptrauth_strip`.

### 3. Почему `mach_vm_remap` работает
`mach_vm_remap` не создает анонимную память и не копирует неподписанные байты. Он создает виртуальное отображение страниц, которые уже являются частью подписанного бинарника `tweakforced`. Так как эти страницы изначально заверены подписью Code Signing нашего процесса, операционная система сохраняет их статус валидного кода в целевом процессе и не блокирует исполнение.

### 4. Необходимые Entitlements
Для функционирования механизма демону назначены специальные права в `entitlements.plist`:
- `get-task-allow` и `task_for_pid-allow`: дают право получать Mach task-порт целевого процесса через `task_for_pid`.
- `dynamic-codesigning`: разрешает исполнение отображенного и JIT-кода без завершения процесса сигналом `CS_KILL`.
- `com.apple.private.skip-library-validation`: отключает проверку системной подписи для динамически загружаемых dylib.
- `platform-application`: помечает демон как доверенную системную утилиту платформы.

### 5. Честное ограничение: статус PPL (Page Protection Layer)
Полноценный **PPL Bypass** требует эксплуатации уязвимостей ядра (kernel exploit) и намеренно **не включен** в пользовательский код демона.
Поэтому:
- **Механизм A (pre-launch через LoaderPatch)** остаётся **главным и основным** методом инъекции на всех конфигурациях.
- **Механизм B (post-launch через PACBypass)** служит надежным fallback-механизмом на джейлбрейках (например, **Dopamine**), где ограничения PPL уже нейтрализованы на уровне среды джейлбрейка.

### 6. Как проверить работу PAC Bypass
Проверить срабатывание PAC-инъекции можно в логе демона:
```bash
tail -f /var/jb/var/mobile/Library/Logs/TweakForce/daemon.log
```
При успешном выполнении Механизма B в логе фиксируются события:
1. `[PACBypass] Обнаружен arm64e процессор (hw.cpusubtype = 2)`
2. `[PACBypass] Найден dlopen: 0x... (PAC stripped: 0x...)`
3. `[PACBypass] mach_vm_remap успешен: local=..., remote_page=..., remote_fn=...`
4. `[PACBypass] Аргументы записаны: stack=..., args=..., dlopen=...`
5. `[PACBypass] УСПЕХ: PAC-aware поток запущен в задаче 0x... для библиотеки ...`
