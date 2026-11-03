# TweakForce — 3_HookFramework/Makefile
# EN: Builds libTweakForceHooks.dylib — the embeddable universal hook framework.
# RU: Собирает libTweakForceHooks.dylib — встраиваемый universal hook framework.
# BUILD: make package THEOS_PACKAGE_SCHEME=roothide
export ARCHS = arm64 arm64e
export TARGET = iphone:clang:latest:15.0
export THEOS_PACKAGE_SCHEME = roothide

include $(THEOS)/makefiles/common.mk

LIBRARY_NAME = libTweakForceHooks
libTweakForceHooks_FILES = Sources/TweakForceHooks.m Sources/HookRegistry.m Sources/DiagnosticReporter.m Sources/fishhook.c
libTweakForceHooks_CFLAGS = -fobjc-arc -Wall -ISources -Wno-error -Wno-nullability-completeness
libTweakForceHooks_FRAMEWORKS = Foundation CoreFoundation UIKit Security
libTweakForceHooks_INSTALL_PATH = /usr/lib/TweakForce

include $(THEOS_MAKE_PATH)/library.mk

# EN: Install the MobileSubstrate/ElleKit filter plist and a DynamicLibraries
#     entry so the hook library is auto-loaded into whitelisted apps.
#     The .dylib itself stays at /usr/lib/TweakForce (used by the daemon's
#     Mechanism A); we add a DynamicLibraries entry as a *relative* symlink so
#     ElleKit discovers the TweakForceHooks.dylib + TweakForceHooks.plist pair
#     without duplicating the binary. The relative target resolves correctly
#     regardless of the rootless /var/jb prefix.
# RU: Устанавливаем filter plist и запись в DynamicLibraries, чтобы ElleKit/
#     Substrate автоматически грузил hook-библиотеку в приложения из whitelist.
#     Сама .dylib остаётся в /usr/lib/TweakForce (её использует Mechanism A
#     демона); в DynamicLibraries кладём относительный symlink, чтобы ElleKit
#     нашёл пару TweakForceHooks.dylib + TweakForceHooks.plist без дублирования
#     бинарника. Относительный путь корректен и с префиксом /var/jb.
SUBSTRATE_DIR = $(THEOS_STAGING_DIR)/Library/MobileSubstrate/DynamicLibraries

internal-stage::
	$(ECHO_NOTHING)mkdir -p "$(SUBSTRATE_DIR)"$(ECHO_END)
	$(ECHO_NOTHING)if [ -f "$(CURDIR)/TweakForceHooks.plist" ]; then \
	cp "$(CURDIR)/TweakForceHooks.plist" "$(SUBSTRATE_DIR)/TweakForceHooks.plist"; \
	elif [ -f "$(THEOS_PROJECT_DIR)/3_HookFramework/TweakForceHooks.plist" ]; then \
	cp "$(THEOS_PROJECT_DIR)/3_HookFramework/TweakForceHooks.plist" "$(SUBSTRATE_DIR)/TweakForceHooks.plist"; \
	elif [ -f "$(THEOS_PROJECT_DIR)/TweakForceHooks.plist" ]; then \
	cp "$(THEOS_PROJECT_DIR)/TweakForceHooks.plist" "$(SUBSTRATE_DIR)/TweakForceHooks.plist"; \
	fi$(ECHO_END)
	$(ECHO_NOTHING)cp "$(THEOS_STAGING_DIR)/usr/lib/TweakForce/libTweakForceHooks.dylib" "$(SUBSTRATE_DIR)/TweakForceHooks.dylib" 2>/dev/null || ln -sf "../../../usr/lib/TweakForce/libTweakForceHooks.dylib" "$(SUBSTRATE_DIR)/TweakForceHooks.dylib"$(ECHO_END)
	$(ECHO_NOTHING)ln -sf "TweakForceHooks.dylib" "$(SUBSTRATE_DIR)/libTweakForceHooks.dylib" 2>/dev/null || true$(ECHO_END)
	$(ECHO_NOTHING)ln -sf "TweakForceHooks.plist" "$(SUBSTRATE_DIR)/libTweakForceHooks.plist" 2>/dev/null || true$(ECHO_END)

after-install::
	install.exec "killall -9 AIDA64 2>/dev/null; true"
