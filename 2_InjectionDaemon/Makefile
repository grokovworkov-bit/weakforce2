# ============================================================================
#  TweakForce — 2_InjectionDaemon/Makefile
# ============================================================================
#  EN: Builds the universal injection daemon as a RootHide LaunchDaemon tool.
#  RU: Собирает universal injection daemon как LaunchDaemon-инструмент RootHide.
#
#  ПОЧЕМУ НУЖНЫ PTRAUTH ФЛАГИ ДЛЯ arm64e:
#  Флаги компилятора Clang (-fptrauth-calls, -fptrauth-returns, -fptrauth-intrinsics)
#  включают генерацию аппаратных инструкций Pointer Authentication для arm64e:
#  1. -fptrauth-calls: генерирует аутентифицированные вызовы функций через BLRAA/BLRAAZ
#     в скомпилированном trampoline, что предотвращает PAC crash при вызове dlopen.
#  2. -fptrauth-returns: защищает адреса возврата на стеке инструкциями PACIASP/AUTIASP.
#  3. -fptrauth-intrinsics: открывает доступ к функциям ptrauth_strip и
#     ptrauth_sign_unauthenticated из <ptrauth.h>, необходимым для подготовки
#     структуры BootstrapArgs и подписания PC удаленного потока.
#
#  BUILD: make package THEOS_PACKAGE_SCHEME=roothide
# ============================================================================

export ARCHS = arm64e
export TARGET = iphone:clang:16.0:15.0
export THEOS_PACKAGE_SCHEME = roothide

include $(THEOS)/makefiles/common.mk

TOOL_NAME = tweakforced

# Исходные файлы: все .m файлы демона + C-реализация PACBypass.c
tweakforced_FILES = $(wildcard Sources/*.m) Sources/PACBypass.c

# Флаги компилятора: ARC, предупреждения, путь к заголовкам, дефайн активации PAC,
# а также ptrauth флаги для поддержки arm64e
tweakforced_CFLAGS = -fobjc-arc -Wall -ISources -DPAC_BYPASS_ENABLED=1 \
                     -fptrauth-calls -fptrauth-returns -fptrauth-intrinsics

# Системные фреймворки: Foundation, CoreFoundation и Security
tweakforced_FRAMEWORKS = Foundation CoreFoundation Security

# Entitlements для task_for_pid и dynamic-codesigning
tweakforced_CODESIGN_FLAGS = -Sentitlements.plist
tweakforced_INSTALL_PATH = /usr/libexec/tweakforce

include $(THEOS_MAKE_PATH)/tool.mk

# Устанавливаем LaunchDaemon plist в rootless-структуру
internal-stage::
        $(ECHO_NOTHING)mkdir -p $(THEOS_STAGING_DIR)/var/jb/Library/LaunchDaemons$(ECHO_END)
        $(ECHO_NOTHING)cp LaunchDaemon.plist $(THEOS_STAGING_DIR)/var/jb/Library/LaunchDaemons/com.tweakforce.daemon.plist$(ECHO_END)
