# TweakForce — 2_InjectionDaemon/Makefile
# EN: Builds the universal injection daemon as a RootHide LaunchDaemon tool.
# RU: Собирает universal injection daemon как LaunchDaemon-инструмент RootHide.
# BUILD: make package THEOS_PACKAGE_SCHEME=roothide
export ARCHS = arm64 arm64e
export TARGET = iphone:clang:16.0:15.0
export THEOS_PACKAGE_SCHEME = roothide

include $(THEOS)/makefiles/common.mk

TOOL_NAME = tweakforced
tweakforced_FILES = $(wildcard Sources/*.m)
tweakforced_CFLAGS = -fobjc-arc -Wall -ISources
tweakforced_FRAMEWORKS = Foundation CoreFoundation
tweakforced_CODESIGN_FLAGS = -Sentitlements.plist
tweakforced_INSTALL_PATH = /usr/libexec/tweakforce

include $(THEOS_MAKE_PATH)/tool.mk

# Install LaunchDaemon plist into the rootless layout.
# Устанавливаем LaunchDaemon plist в rootless-структуру.
internal-stage::
	$(ECHO_NOTHING)mkdir -p $(THEOS_STAGING_DIR)/var/jb/Library/LaunchDaemons$(ECHO_END)
	$(ECHO_NOTHING)cp LaunchDaemon.plist $(THEOS_STAGING_DIR)/var/jb/Library/LaunchDaemons/com.tweakforce.daemon.plist$(ECHO_END)
