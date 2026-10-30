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
