# ============================================================================
#  TweakForce — 1_LoaderPatch/Makefile
# ============================================================================
#  EN: Builds the bootstrap loader patch as a RootHide (rootless) tweak.
#  RU: Собирает патч bootstrap loader'а как tweak для RootHide (rootless).
#
#  BUILD:   make package THEOS_PACKAGE_SCHEME=roothide
#  INSTALL: make install THEOS_DEVICE_IP=<ip>
# ============================================================================

export ARCHS = arm64 arm64e
export TARGET = iphone:clang:latest:15.0
export THEOS_PACKAGE_SCHEME = roothide

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = TweakForceLoaderPatch

TweakForceLoaderPatch_FILES = LoaderPatch.x AppListManager.m
TweakForceLoaderPatch_CFLAGS = -fobjc-arc -Wall
TweakForceLoaderPatch_FRAMEWORKS = Foundation
TweakForceLoaderPatch_CODESIGN_FLAGS = -Sentitlements.plist
# EN: ElleKit on RootHide; falls back to substrate if ellekit missing.
# RU: ElleKit на RootHide; откат на substrate, если ellekit отсутствует.
TweakForceLoaderPatch_LIBRARIES = substrate

include $(THEOS_MAKE_PATH)/tweak.mk

# EN: Loader patch targets the bootstrap process, not a user app.
# RU: Патч нацелен на процесс bootstrap, а не на пользовательское приложение.
after-install::
	@echo "[TweakForce] LoaderPatch installed. Respring or restart bootstrapd to apply."
