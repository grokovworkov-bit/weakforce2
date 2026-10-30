# ============================================================================
#  TweakForce — Master Makefile
# ============================================================================
#  EN: Aggregates subprojects for building all components:
#      1_LoaderPatch, 2_InjectionDaemon, 3_HookFramework.
#  RU: Собирает все подпроекты:
#      1_LoaderPatch, 2_InjectionDaemon, 3_HookFramework.
#
#  BUILD:
#      make package THEOS_PACKAGE_SCHEME=roothide FINALPACKAGE=1
#      make package THEOS_PACKAGE_SCHEME=rootless FINALPACKAGE=1
# ============================================================================

export TARGET = iphone:clang:latest:15.0
export ARCHS ?= arm64e

ifeq ($(THEOS_PACKAGE_SCHEME),)
        export THEOS_PACKAGE_SCHEME = roothide
endif

include $(THEOS)/makefiles/common.mk

SUBPROJECTS += 1_LoaderPatch
SUBPROJECTS += 2_InjectionDaemon
SUBPROJECTS += 3_HookFramework

include $(THEOS_MAKE_PATH)/aggregate.mk
