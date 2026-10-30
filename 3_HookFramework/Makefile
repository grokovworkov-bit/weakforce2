# TweakForce — 3_HookFramework/Makefile
# EN: Builds libTweakForceHooks.dylib — the embeddable universal hook framework.
# RU: Собирает libTweakForceHooks.dylib — встраиваемый universal hook framework.
# BUILD: make package THEOS_PACKAGE_SCHEME=roothide
export ARCHS = arm64 arm64e
export TARGET = iphone:clang:16.0:15.0
export THEOS_PACKAGE_SCHEME = roothide

include $(THEOS)/makefiles/common.mk

LIBRARY_NAME = libTweakForceHooks
libTweakForceHooks_FILES = Sources/TweakForceHooks.m Sources/HookRegistry.m Sources/DiagnosticReporter.m Sources/fishhook.c
libTweakForceHooks_CFLAGS = -fobjc-arc -Wall -ISources
libTweakForceHooks_FRAMEWORKS = Foundation CoreFoundation UIKit
libTweakForceHooks_INSTALL_PATH = /usr/lib/TweakForce

include $(THEOS_MAKE_PATH)/library.mk
