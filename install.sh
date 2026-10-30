#!/usr/bin/env bash
# ============================================================================
#  TweakForce — install.sh
#  EN: Builds all Theos components and installs them on the device over SSH,
#      drops the config, loads the LaunchDaemon and reloads launchd.
#  RU: Собирает все Theos-компоненты, ставит их на устройство по SSH, кладёт
#      конфиг, загружает LaunchDaemon и перезагружает launchd.
#
#  USAGE / ИСПОЛЬЗОВАНИЕ:
#      export THEOS=/opt/theos
#      export THEOS_DEVICE_IP=192.168.1.50      # iPhone IP
#      export THEOS_DEVICE_PORT=22              # optional
#      ./install.sh
# ============================================================================
set -euo pipefail

# --- 1) Preconditions / Предусловия ----------------------------------------
if [[ -z "${THEOS:-}" || ! -d "$THEOS" ]]; then
    echo "[TweakForce] ОШИБКА: переменная THEOS не задана или не найдена каталог Theos." >&2
    echo "            Установите Theos и 'export THEOS=/opt/theos'." >&2
    exit 1
fi
if [[ -z "${THEOS_DEVICE_IP:-}" ]]; then
    echo "[TweakForce] ОШИБКА: THEOS_DEVICE_IP не задан (IP вашего iPhone)." >&2
    exit 1
fi
PORT="${THEOS_DEVICE_PORT:-22}"
SSH="ssh -p ${PORT} root@${THEOS_DEVICE_IP}"
SCP="scp -P ${PORT}"
ROOT=$(cd "$(dirname "$0")" && pwd)

echo "[TweakForce] Theos: $THEOS"
echo "[TweakForce] Устройство: root@${THEOS_DEVICE_IP}:${PORT}"

# --- 2) Build all components / Сборка всех компонентов ----------------------
build() {
    local dir="$1"
    echo "[TweakForce] Сборка $dir ..."
    ( cd "$ROOT/$dir" && make package THEOS_PACKAGE_SCHEME=roothide )
}
build 1_LoaderPatch
build 2_InjectionDaemon
build 3_HookFramework
# TestApp собирается в Xcode (Swift). Здесь не пакуется.

# --- 3) Install .deb packages / Установка .deb пакетов ----------------------
echo "[TweakForce] Загрузка и установка пакетов на устройство ..."
for pkg in $(find "$ROOT" -name '*.deb' -path '*/packages/*'); do
    echo "  -> $pkg"
    $SCP "$pkg" "root@${THEOS_DEVICE_IP}:/tmp/" 
    $SSH -n "dpkg -i /tmp/$(basename "$pkg")"
done

# --- 4) Drop config / Копирование конфига ----------------------------------
echo "[TweakForce] Установка конфига tweakforce.json ..."
$SSH -n "mkdir -p /var/jb/etc /var/jb/var/mobile/Library/TweakForce /var/jb/var/mobile/Library/Logs/TweakForce"
$SCP "$ROOT/config/tweakforce.json" "root@${THEOS_DEVICE_IP}:/var/jb/etc/tweakforce.json"

# --- 5) LaunchDaemon plist / plist LaunchDaemon -----------------------------
echo "[TweakForce] Установка LaunchDaemon ..."
$SCP "$ROOT/2_InjectionDaemon/LaunchDaemon.plist" \
     "root@${THEOS_DEVICE_IP}:/var/jb/Library/LaunchDaemons/com.tweakforce.daemon.plist"

# --- 6) Reload launchd / Перезагрузка launchd ------------------------------
echo "[TweakForce] Перезапуск daemon через launchctl ..."
$SSH -n "launchctl bootout system /var/jb/Library/LaunchDaemons/com.tweakforce.daemon.plist 2>/dev/null || true"
$SSH -n "launchctl bootstrap system /var/jb/Library/LaunchDaemons/com.tweakforce.daemon.plist"
$SSH -n "launchctl kickstart -k system/com.tweakforce.daemon 2>/dev/null || true"

# --- 7) Log pointer / Ссылка на лог ----------------------------------------
echo ""
echo "[TweakForce] ГОТОВО. Лог daemon:"
echo "    $SSH 'tail -f /var/jb/var/mobile/Library/Logs/TweakForce/daemon.log'"
echo ""
echo "[TweakForce] НАПОМИНАНИЕ:"
echo "    1) Добавьте тестовое приложение И com.finalwire.aida64 в App List RootHide Bootstrap."
echo "    2) Включите injection для них в Manager app или в tweakforce.json."
echo "    3) Перезапустите приложение — должен загрузиться libTweakForceHooks."
