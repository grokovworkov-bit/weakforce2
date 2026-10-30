#!/usr/bin/env bash
# ============================================================================
#  TweakForce — package_all_in_one.sh
#  EN: Combines the built subproject debs into a single all-in-one .deb package.
#  RU: Объединяет собранные deb подпроектов в единый all-in-one пакет .deb.
# ============================================================================
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="${ROOT_DIR}/build_suite"
STAGING_DIR="${BUILD_DIR}/staging"
SCHEME="${THEOS_PACKAGE_SCHEME:-roothide}"

echo "[TweakForce] Создание объединенного пакета для схемы: ${SCHEME}..."

rm -rf "${BUILD_DIR}"
mkdir -p "${STAGING_DIR}/DEBIAN"

# Распаковываем все собранные .deb пакеты в staging
DEBS=$(find "${ROOT_DIR}" -name "*.deb" -path "*/packages/*")
if [ -z "${DEBS}" ]; then
    echo "[TweakForce] Ошибка: Не найдены собранные .deb пакеты в поддиректориях." >&2
    echo "Сначала выполните сборку (make package)." >&2
    exit 1
fi

for deb in ${DEBS}; do
    echo "  -> Извлечение $(basename "$deb")..."
    dpkg-deb -x "$deb" "${STAGING_DIR}"
done

# Создаем объединенный control файл
cat << 'EOF' > "${STAGING_DIR}/DEBIAN/control"
Package: com.tweakforce.suite
Name: TweakForce Suite (All-In-One)
Version: 1.0.0
Architecture: iphoneos-arm64e
Description: Complete TweakForce suite: RootHide LoaderPatch, PAC-aware Injection Daemon, and Device Spoofing Hooks. / Полный комплект TweakForce: патч лоадера, демон инъекции и хуки спуфинга.
Maintainer: TweakForce
Author: TweakForce
Section: Tweaks
Priority: optional
Depends: ellekit | mobilesubstrate
EOF

# Копируем postinst и prerm скрипты
cp "${ROOT_DIR}/2_InjectionDaemon/layout/DEBIAN/postinst" "${STAGING_DIR}/DEBIAN/postinst"
cp "${ROOT_DIR}/2_InjectionDaemon/layout/DEBIAN/prerm" "${STAGING_DIR}/DEBIAN/prerm"
chmod 755 "${STAGING_DIR}/DEBIAN/postinst" "${STAGING_DIR}/DEBIAN/prerm"

# Собираем итоговый пакет
OUTPUT_DIR="${ROOT_DIR}/packages"
mkdir -p "${OUTPUT_DIR}"
OUTPUT_DEB="${OUTPUT_DIR}/com.tweakforce.suite_1.0.0_${SCHEME}_iphoneos-arm64e.deb"

dpkg-deb -b "${STAGING_DIR}" "${OUTPUT_DEB}"
echo "[TweakForce] Итоговый пакет успешно создан: ${OUTPUT_DEB}"
rm -rf "${BUILD_DIR}"
