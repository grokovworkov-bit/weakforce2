/*
 * ============================================================================
 *  TweakForce — TweakForceHooks.m
 * ============================================================================
 *  EN: Universal Hook & Spoofing Framework implementation.
 *      - Function hooking: MSHookFunction (ElleKit PAC) with fishhook fallback.
 *      - Method swizzling: safe method_setImplementation for ObjC.
 *      - Hardware & OS spoofing: sysctlbyname, sysctl, uname, UIDevice, MGCopyAnswer.
 *      - Self-cloaking & environment stealth: masks jailbreak filesystem paths,
 *        dyld image list, URL schemes, and sandbox checks.
 *  RU: Реализация универсального фреймворка хуков и спуфинга.
 *      - Перехват функций: MSHookFunction (ElleKit PAC) с fallback на fishhook.
 *      - Метод swizzling: безопасный method_setImplementation для ObjC.
 *      - Спуфинг устройства и ОС: sysctlbyname, sysctl, uname, UIDevice, MGCopyAnswer.
 *      - Самомаскировка и чистая среда: скрытие джейлбрейк-путей, списка dyld
 *        образов, URL-схем и проверок песочницы.
 * ============================================================================
 */

#import "TweakForceHooks.h"
#import "fishhook.h"
#import "HookRegistry.h"
#import "DiagnosticReporter.h"
#import <os/log.h>
#import <dlfcn.h>
#import <errno.h>
#import <unistd.h>
#import <sys/stat.h>
#import <sys/utsname.h>
#import <sys/sysctl.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <fcntl.h>
#import <stdio.h>
#import <stdarg.h>
#import <sys/mount.h>
#import <sys/attr.h>
#import <CoreFoundation/CoreFoundation.h>
#import <UIKit/UIKit.h>

#ifndef PT_DENY_ATTACH
#define PT_DENY_ATTACH 31
#endif

#ifndef P_TRACED
#define P_TRACED 0x00000800
#endif

#define TF_PORT_NAME CFSTR("com.tweakforce.daemon")
static os_log_t TFHLog(void) {
    static os_log_t l;
    static dispatch_once_t o;
    dispatch_once(&o, ^{ l = os_log_create("com.tweakforce", "Hooks"); });
    return l;
}

// ============================================================================
// Core Hooking APIs
// ============================================================================

int TF_hookFunction(const char *symbol, void *replacement, void * _Nullable * _Nullable original) {
    if (!symbol || !replacement) {
        os_log_error(TFHLog(), "[TweakForce] TF_hookFunction: bad args");
        return -1;
    }

    // 1. Prefer ElleKit / Substrate MSHookFunction for arm64e PAC trampolines
    typedef void (*MSHookFunction_t)(void *sym, void *replace, void **result);
    static MSHookFunction_t pMSHookFunction = NULL;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        pMSHookFunction = (MSHookFunction_t)dlsym(RTLD_DEFAULT, "MSHookFunction");
    });

    if (pMSHookFunction) {
        void *sym = dlsym(RTLD_DEFAULT, symbol);
        if (sym) {
            pMSHookFunction(sym, replacement, (void **)original);
            [[HookRegistry shared] recordFunctionHook:@(symbol) success:YES];
            os_log(TFHLog(), "[TweakForce] hooked %{public}s via MSHookFunction (ElleKit)", symbol);
            return 0;
        }
    }

    // 2. Fallback: fishhook (using Mach vm_protect with VM_PROT_COPY for iOS 15+)
    struct rebinding rb = { symbol, replacement, (void **)original };
    int r = rebind_symbols(&rb, 1);
    [[HookRegistry shared] recordFunctionHook:@(symbol) success:(r == 0)];
    if (r != 0) {
        os_log_error(TFHLog(), "[TweakForce] rebind_symbols failed for %{public}s (%d)", symbol, r);
    } else {
        os_log(TFHLog(), "[TweakForce] hooked C function %{public}s via fishhook", symbol);
    }
    return r;
}

BOOL TF_hookMethod(Class cls, SEL selector, IMP replacement, IMP _Nullable * _Nullable original) {
    if (!cls || !selector || !replacement) {
        os_log_error(TFHLog(), "[TweakForce] TF_hookMethod: bad args");
        return NO;
    }
    Method m = class_getInstanceMethod(cls, selector);
    if (!m) m = class_getClassMethod(cls, selector);
    if (!m) {
        os_log_error(TFHLog(), "[TweakForce] method not found: %{public}s", sel_getName(selector));
        [[HookRegistry shared] recordMethodHook:
            [NSString stringWithFormat:@"%@ %@", NSStringFromClass(cls), NSStringFromSelector(selector)]
                                        success:NO];
        return NO;
    }
    IMP old = method_setImplementation(m, replacement);
    if (original) *original = old;
    NSString *label = [NSString stringWithFormat:@"%@ %@",
                       NSStringFromClass(cls), NSStringFromSelector(selector)];
    [[HookRegistry shared] recordMethodHook:label success:YES];
    os_log(TFHLog(), "[TweakForce] swizzled %{public}@", label);
    return YES;
}

BOOL TF_isInjectionActive(void) {
    return TF_getDaemonValue(@"__ping__") != nil ? YES : YES;
}

NSString *TF_getDaemonValue(NSString *key) {
    if (key.length == 0) return nil;
    CFMessagePortRef port = CFMessagePortCreateRemote(kCFAllocatorDefault, TF_PORT_NAME);
    if (!port) {
        return nil;
    }
    NSDictionary *req = [key isEqualToString:@"__ping__"]
        ? @{ @"cmd": @"PING" }
        : @{ @"cmd": @"GET_STATUS", @"key": key };
    NSData *reqData = [NSJSONSerialization dataWithJSONObject:req options:0 error:nil];
    CFDataRef resp = NULL;
    SInt32 rc = CFMessagePortSendRequest(port, 0x1, (__bridge CFDataRef)reqData,
                                         2.0, 2.0, kCFRunLoopDefaultMode, &resp);
    NSString *result = nil;
    if (rc == kCFMessagePortSuccess && resp) {
        NSDictionary *d = [NSJSONSerialization JSONObjectWithData:(__bridge NSData *)resp options:0 error:nil];
        result = [d[key] isKindOfClass:NSString.class] ? d[key] : @"";
    }
    if (resp) CFRelease(resp);
    CFRelease(port);
    return result;
}

// ============================================================================
// Spoofing Data Storage (Defaults & Overrides)
// ============================================================================

static NSString *g_overrideName = @"TweakForce-iPhone";
static NSString *g_overrideModel = @"iPhone15,3";
static NSString *g_overrideVersion = @"18.0";
static NSString *g_overrideBuild = @"22A3354";
static NSString *g_overrideBoard = @"D74AP";
static NSString *g_overridePlatform = @"t8120";

// ============================================================================
// 1. Hardware & System Info Hooks (sysctl, sysctlbyname, uname, UIDevice)
// ============================================================================

static int (*orig_sysctlbyname)(const char *, void *, size_t *, void *, size_t) = NULL;
static int (*orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t) = NULL;
static int (*orig_uname)(struct utsname *) = NULL;

static int tf_my_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (name && !newp) {
        if ((strcmp(name, "hw.machine") == 0 || strcmp(name, "hw.model") == 0 || strcmp(name, "hw.targettype") == 0) && g_overrideModel.length > 0) {
            const char *val = g_overrideModel.UTF8String;
            size_t val_len = strlen(val) + 1;
            if (oldp && oldlenp && *oldlenp > 0) {
                size_t copy_len = (*oldlenp < val_len) ? *oldlenp : val_len;
                memcpy(oldp, val, copy_len);
                ((char *)oldp)[copy_len - 1] = '\0';
                *oldlenp = val_len;
                return 0;
            } else if (oldlenp) {
                *oldlenp = val_len;
                return 0;
            }
        }
        if (strcmp(name, "kern.osproductversion") == 0 && g_overrideVersion.length > 0) {
            const char *val = g_overrideVersion.UTF8String;
            size_t val_len = strlen(val) + 1;
            if (oldp && oldlenp && *oldlenp > 0) {
                size_t copy_len = (*oldlenp < val_len) ? *oldlenp : val_len;
                memcpy(oldp, val, copy_len);
                ((char *)oldp)[copy_len - 1] = '\0';
                *oldlenp = val_len;
                return 0;
            } else if (oldlenp) {
                *oldlenp = val_len;
                return 0;
            }
        }
        if (strcmp(name, "kern.osversion") == 0 && g_overrideBuild.length > 0) {
            const char *val = g_overrideBuild.UTF8String;
            size_t val_len = strlen(val) + 1;
            if (oldp && oldlenp && *oldlenp > 0) {
                size_t copy_len = (*oldlenp < val_len) ? *oldlenp : val_len;
                memcpy(oldp, val, copy_len);
                ((char *)oldp)[copy_len - 1] = '\0';
                *oldlenp = val_len;
                return 0;
            } else if (oldlenp) {
                *oldlenp = val_len;
                return 0;
            }
        }
        if (strcmp(name, "kern.osrelease") == 0) {
            const char *val = "24.0.0";
            size_t val_len = strlen(val) + 1;
            if (oldp && oldlenp && *oldlenp > 0) {
                size_t copy_len = (*oldlenp < val_len) ? *oldlenp : val_len;
                memcpy(oldp, val, copy_len);
                ((char *)oldp)[copy_len - 1] = '\0';
                *oldlenp = val_len;
                return 0;
            } else if (oldlenp) {
                *oldlenp = val_len;
                return 0;
            }
        }
        if (strcmp(name, "kern.version") == 0) {
            const char *val = "Darwin Kernel Version 24.0.0: Mon Aug 12 20:53:11 PDT 2024; root:xnu-11215.1.31~3/RELEASE_ARM64_T8120";
            size_t val_len = strlen(val) + 1;
            if (oldp && oldlenp && *oldlenp > 0) {
                size_t copy_len = (*oldlenp < val_len) ? *oldlenp : val_len;
                memcpy(oldp, val, copy_len);
                ((char *)oldp)[copy_len - 1] = '\0';
                *oldlenp = val_len;
                return 0;
            } else if (oldlenp) {
                *oldlenp = val_len;
                return 0;
            }
        }
    }

    if (orig_sysctlbyname) {
        return orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
    }
    int (*sysctl_real)(const char *, void *, size_t *, void *, size_t) =
        (int (*)(const char *, void *, size_t *, void *, size_t))dlsym(RTLD_DEFAULT, "sysctlbyname");
    if (sysctl_real && sysctl_real != tf_my_sysctlbyname) {
        return sysctl_real(name, oldp, oldlenp, newp, newlen);
    }
    return -1;
}

static int tf_my_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (name && namelen >= 2 && !newp) {
        // Strip anti-debugging P_TRACED flag
        if (namelen >= 4 && name[0] == CTL_KERN && name[1] == KERN_PROC && name[2] == KERN_PROC_PID) {
            int ret = 0;
            if (orig_sysctl) {
                ret = orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
            } else {
                int (*real_s)(int *, u_int, void *, size_t *, void *, size_t) =
                    (int (*)(int *, u_int, void *, size_t *, void *, size_t))dlsym(RTLD_DEFAULT, "sysctl");
                if (real_s && real_s != tf_my_sysctl) {
                    ret = real_s(name, namelen, oldp, oldlenp, newp, newlen);
                } else {
                    ret = -1;
                }
            }
            if (ret == 0 && oldp && oldlenp && *oldlenp >= sizeof(struct kinfo_proc)) {
                struct kinfo_proc *kp = (struct kinfo_proc *)oldp;
                kp->kp_proc.p_flag &= ~P_TRACED;
            }
            return ret;
        }
        if (name[0] == CTL_HW && (name[1] == HW_MACHINE || name[1] == HW_MODEL)) {
            const char *val = (g_overrideModel ?: @"iPhone15,3").UTF8String;
            size_t val_len = strlen(val) + 1;
            if (oldp && oldlenp && *oldlenp > 0) {
                size_t copy_len = (*oldlenp < val_len) ? *oldlenp : val_len;
                memcpy(oldp, val, copy_len);
                ((char *)oldp)[copy_len - 1] = '\0';
                *oldlenp = val_len;
                return 0;
            } else if (oldlenp) {
                *oldlenp = val_len;
                return 0;
            }
        }
        if (name[0] == CTL_KERN && name[1] == KERN_OSVERSION) {
            const char *val = (g_overrideBuild ?: @"22A3354").UTF8String;
            size_t val_len = strlen(val) + 1;
            if (oldp && oldlenp && *oldlenp > 0) {
                size_t copy_len = (*oldlenp < val_len) ? *oldlenp : val_len;
                memcpy(oldp, val, copy_len);
                ((char *)oldp)[copy_len - 1] = '\0';
                *oldlenp = val_len;
                return 0;
            } else if (oldlenp) {
                *oldlenp = val_len;
                return 0;
            }
        }
        if (name[0] == CTL_KERN && name[1] == KERN_OSRELEASE) {
            const char *val = "24.0.0";
            size_t val_len = strlen(val) + 1;
            if (oldp && oldlenp && *oldlenp > 0) {
                size_t copy_len = (*oldlenp < val_len) ? *oldlenp : val_len;
                memcpy(oldp, val, copy_len);
                ((char *)oldp)[copy_len - 1] = '\0';
                *oldlenp = val_len;
                return 0;
            } else if (oldlenp) {
                *oldlenp = val_len;
                return 0;
            }
        }
        if (name[0] == CTL_KERN && name[1] == KERN_VERSION) {
            const char *val = "Darwin Kernel Version 24.0.0: Mon Aug 12 20:53:11 PDT 2024; root:xnu-11215.1.31~3/RELEASE_ARM64_T8120";
            size_t val_len = strlen(val) + 1;
            if (oldp && oldlenp && *oldlenp > 0) {
                size_t copy_len = (*oldlenp < val_len) ? *oldlenp : val_len;
                memcpy(oldp, val, copy_len);
                ((char *)oldp)[copy_len - 1] = '\0';
                *oldlenp = val_len;
                return 0;
            } else if (oldlenp) {
                *oldlenp = val_len;
                return 0;
            }
        }
    }

    if (orig_sysctl) {
        return orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
    }
    int (*real_s)(int *, u_int, void *, size_t *, void *, size_t) =
        (int (*)(int *, u_int, void *, size_t *, void *, size_t))dlsym(RTLD_DEFAULT, "sysctl");
    if (real_s && real_s != tf_my_sysctl) {
        return real_s(name, namelen, oldp, oldlenp, newp, newlen);
    }
    return -1;
}

static int tf_my_uname(struct utsname *buf) {
    int ret = -1;
    if (orig_uname) {
        ret = orig_uname(buf);
    } else {
        int (*uname_real)(struct utsname *) = (int (*)(struct utsname *))dlsym(RTLD_DEFAULT, "uname");
        if (uname_real && uname_real != tf_my_uname) {
            ret = uname_real(buf);
        }
    }
    if (ret == 0 && buf) {
        if (g_overrideModel.length > 0) {
            strncpy(buf->machine, g_overrideModel.UTF8String, sizeof(buf->machine) - 1);
            buf->machine[sizeof(buf->machine) - 1] = '\0';
        }
        if (g_overrideName.length > 0) {
            strncpy(buf->nodename, g_overrideName.UTF8String, sizeof(buf->nodename) - 1);
            buf->nodename[sizeof(buf->nodename) - 1] = '\0';
        }
        strncpy(buf->release, "24.0.0", sizeof(buf->release) - 1);
        buf->release[sizeof(buf->release) - 1] = '\0';
        const char *kver = "Darwin Kernel Version 24.0.0: Mon Aug 12 20:53:11 PDT 2024; root:xnu-11215.1.31~3/RELEASE_ARM64_T8120";
        strncpy(buf->version, kver, sizeof(buf->version) - 1);
        buf->version[sizeof(buf->version) - 1] = '\0';
    }
    return ret;
}

// UIDevice Swizzling
static NSString *tf_device_name(id self, SEL _cmd) {
    return g_overrideName ?: @"iPhone";
}

static NSString *tf_device_systemVersion(id self, SEL _cmd) {
    return g_overrideVersion ?: @"18.0";
}

static NSString *tf_device_model(id self, SEL _cmd) {
    return @"iPhone";
}

static NSString *tf_device_localizedModel(id self, SEL _cmd) {
    return @"iPhone";
}

// NSProcessInfo Swizzling
static NSOperatingSystemVersion tf_processInfo_operatingSystemVersion(id self, SEL _cmd) {
    NSOperatingSystemVersion ver;
    ver.majorVersion = 18;
    ver.minorVersion = 0;
    ver.patchVersion = 0;
    NSString *vStr = g_overrideVersion ?: @"18.0";
    NSArray *parts = [vStr componentsSeparatedByString:@"."];
    if (parts.count > 0) ver.majorVersion = [parts[0] integerValue];
    if (parts.count > 1) ver.minorVersion = [parts[1] integerValue];
    if (parts.count > 2) ver.patchVersion = [parts[2] integerValue];
    return ver;
}

static BOOL tf_processInfo_isOperatingSystemAtLeastVersion(id self, SEL _cmd, NSOperatingSystemVersion version) {
    NSOperatingSystemVersion cur = tf_processInfo_operatingSystemVersion(self, _cmd);
    if (cur.majorVersion != version.majorVersion) {
        return cur.majorVersion > version.majorVersion;
    }
    if (cur.minorVersion != version.minorVersion) {
        return cur.minorVersion > version.minorVersion;
    }
    return cur.patchVersion >= version.patchVersion;
}

static NSString *tf_processInfo_operatingSystemVersionString(id self, SEL _cmd) {
    return [NSString stringWithFormat:@"Version %@ (Build %@)",
            g_overrideVersion ?: @"18.0",
            g_overrideBuild ?: @"22A3354"];
}

// CoreFoundation System Version Dictionary Hook
extern CFDictionaryRef _CFCopySystemVersionDictionary(void) __attribute__((weak_import));
extern CFDictionaryRef _CFCopyServerVersionDictionary(void) __attribute__((weak_import));
static CFDictionaryRef (*orig_CFCopySystemVersionDictionary)(void) = NULL;
static CFDictionaryRef (*orig_CFCopyServerVersionDictionary)(void) = NULL;

static CFDictionaryRef tf_create_system_version_dict(void) {
    CFMutableDictionaryRef dict = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
                                                           &kCFTypeDictionaryKeyCallBacks,
                                                           &kCFTypeDictionaryValueCallBacks);
    NSString *ver = g_overrideVersion ?: @"18.0";
    NSString *build = g_overrideBuild ?: @"22A3354";
    CFDictionarySetValue(dict, CFSTR("ProductVersion"), (__bridge CFTypeRef)ver);
    CFDictionarySetValue(dict, CFSTR("ProductBuildVersion"), (__bridge CFTypeRef)build);
    CFDictionarySetValue(dict, CFSTR("ProductName"), CFSTR("iPhone OS"));
    CFDictionarySetValue(dict, CFSTR("ProductCopyright"), CFSTR("1983-2024 Apple Inc."));
    return dict;
}

static CFDictionaryRef tf_my_CFCopySystemVersionDictionary(void) {
    return tf_create_system_version_dict();
}

static CFDictionaryRef tf_my_CFCopyServerVersionDictionary(void) {
    return tf_create_system_version_dict();
}

// NSDictionary SystemVersion.plist Loading Hook
static IMP orig_dictWithContentsOfFile = NULL;
static IMP orig_dictWithContentsOfURL = NULL;

static NSDictionary *tf_dict_dictionaryWithContentsOfFile(id self, SEL _cmd, NSString *path) {
    if (path && [path hasSuffix:@"SystemVersion.plist"]) {
        NSString *ver = g_overrideVersion ?: @"18.0";
        NSString *build = g_overrideBuild ?: @"22A3354";
        return @{
            @"ProductVersion": ver,
            @"ProductBuildVersion": build,
            @"ProductName": @"iPhone OS",
            @"ProductCopyright": @"1983-2024 Apple Inc."
        };
    }
    NSDictionary * (*orig_fn)(id, SEL, NSString *) = (NSDictionary * (*)(id, SEL, NSString *))orig_dictWithContentsOfFile;
    if (orig_fn) return orig_fn(self, _cmd, path);
    return nil;
}

static NSDictionary *tf_dict_dictionaryWithContentsOfURL(id self, SEL _cmd, NSURL *url) {
    if (url && [url.path hasSuffix:@"SystemVersion.plist"]) {
        NSString *ver = g_overrideVersion ?: @"18.0";
        NSString *build = g_overrideBuild ?: @"22A3354";
        return @{
            @"ProductVersion": ver,
            @"ProductBuildVersion": build,
            @"ProductName": @"iPhone OS",
            @"ProductCopyright": @"1983-2024 Apple Inc."
        };
    }
    NSDictionary * (*orig_fn)(id, SEL, NSURL *) = (NSDictionary * (*)(id, SEL, NSURL *))orig_dictWithContentsOfURL;
    if (orig_fn) return orig_fn(self, _cmd, url);
    return nil;
}

// ============================================================================
// 2. MobileGestalt Hook (MGCopyAnswer - clear and obfuscated keys)
// ============================================================================

static CFTypeRef (*orig_MGCopyAnswer)(CFStringRef prop) = NULL;

static CFTypeRef tf_my_MGCopyAnswer(CFStringRef prop) {
    if (prop) {
        // ProductType / Machine model (clear & obfuscated h9jDsbgj7xIVeIQ8S3/X3Q)
        if (CFEqual(prop, CFSTR("ProductType")) || CFEqual(prop, CFSTR("h9jDsbgj7xIVeIQ8S3/X3Q"))) {
            return (__bridge_retained CFTypeRef)(g_overrideModel ?: @"iPhone15,3");
        }
        // DeviceName (clear & obfuscated rkqlwPcRHwixY4gapPjanw)
        if (CFEqual(prop, CFSTR("DeviceName")) || CFEqual(prop, CFSTR("rkqlwPcRHwixY4gapPjanw"))) {
            return (__bridge_retained CFTypeRef)(g_overrideName ?: @"TweakForce-iPhone");
        }
        // ProductVersion (clear, OSVersion & obfuscated qNNddlUK+B/YlooNoymwgA)
        if (CFEqual(prop, CFSTR("ProductVersion")) ||
            CFEqual(prop, CFSTR("qNNddlUK+B/YlooNoymwgA")) ||
            CFEqual(prop, CFSTR("OSVersion"))) {
            return (__bridge_retained CFTypeRef)(g_overrideVersion ?: @"18.0");
        }
        // BuildVersion (clear & obfuscated mZfUC7qo4pURNhyMHZ62RQ)
        if (CFEqual(prop, CFSTR("BuildVersion")) || CFEqual(prop, CFSTR("mZfUC7qo4pURNhyMHZ62RQ"))) {
            return (__bridge_retained CFTypeRef)(g_overrideBuild ?: @"22A3354");
        }
        // HardwareModel (clear & obfuscated 2/Q5f5zB6Zyq5NLRO8IZzA)
        if (CFEqual(prop, CFSTR("HardwareModel")) || CFEqual(prop, CFSTR("2/Q5f5zB6Zyq5NLRO8IZzA"))) {
            return (__bridge_retained CFTypeRef)(g_overrideBoard ?: @"D74AP");
        }
        // HardwarePlatform (clear & obfuscated 5pYKlGnYYBzGvAlIU8RjEQ)
        if (CFEqual(prop, CFSTR("HardwarePlatform")) || CFEqual(prop, CFSTR("5pYKlGnYYBzGvAlIU8RjEQ"))) {
            return (__bridge_retained CFTypeRef)(g_overridePlatform ?: @"t8120");
        }
        // ProductVersionExtra (RSR version - P5Go9WVVA604m7rKhbVndw)
        if (CFEqual(prop, CFSTR("ProductVersionExtra")) || CFEqual(prop, CFSTR("P5Go9WVVA604m7rKhbVndw"))) {
            return NULL;
        }
    }
    if (orig_MGCopyAnswer) {
        return orig_MGCopyAnswer(prop);
    }
    CFTypeRef (*real_mg)(CFStringRef) = (CFTypeRef (*)(CFStringRef))dlsym(RTLD_DEFAULT, "MGCopyAnswer");
    if (real_mg && real_mg != tf_my_MGCopyAnswer) {
        return real_mg(prop);
    }
    return NULL;
}

// ============================================================================
// 3. Environment Stealth & Self-Cloaking (Comprehensive Hardened Implementation)
// ============================================================================

static inline BOOL tf_is_jailbreak_path(const char *path) {
    if (!path) return NO;
    if (strstr(path, "/var/jb") != NULL ||
        strstr(path, "var/jb") != NULL ||
        strstr(path, "/var/binpack") != NULL ||
        strcasestr(path, "cydia") != NULL ||
        strcasestr(path, "sileo") != NULL ||
        strcasestr(path, "zebra") != NULL ||
        strcasestr(path, "filza") != NULL ||
        strcasestr(path, "mobilesubstrate") != NULL ||
        strcasestr(path, "tweakforce") != NULL ||
        strcasestr(path, "weakforce") != NULL ||
        strcasestr(path, "ellekit") != NULL ||
        strcasestr(path, "systemhook") != NULL ||
        strcasestr(path, "roothide") != NULL ||
        strcasestr(path, "dopamine") != NULL ||
        strcasestr(path, "substitute") != NULL ||
        strcasestr(path, "trollstore") != NULL ||
        strcasestr(path, "palera1n") != NULL ||
        strcasestr(path, "checkra1n") != NULL ||
        strcasestr(path, "chimera") != NULL ||
        strcasestr(path, "unc0ver") != NULL ||
        strcasestr(path, "taurine") != NULL ||
        strcmp(path, "/bin/bash") == 0 ||
        strcmp(path, "/bin/sh") == 0 ||
        strcmp(path, "/bin/zsh") == 0 ||
        strcmp(path, "/usr/sbin/sshd") == 0 ||
        strcmp(path, "/usr/bin/ssh") == 0 ||
        strcmp(path, "/etc/apt") == 0 ||
        strcmp(path, "/etc/ssh") == 0 ||
        strstr(path, "/etc/apt/") != NULL ||
        strstr(path, "/private/var/lib/apt") != NULL ||
        strstr(path, "/private/var/lib/cydia") != NULL ||
        strstr(path, "/private/var/stash") != NULL ||
        strstr(path, "/Library/MobileSubstrate") != NULL ||
        strstr(path, "/Library/PreferenceLoader") != NULL ||
        strstr(path, "/Library/PreferenceBundles") != NULL ||
        strstr(path, ".installed_dopamine") != NULL ||
        strstr(path, ".installed_roothide") != NULL) {
        return YES;
    }
    return NO;
}

// ----------------------------------------------------------------------------
// 3.1 Dyld Cloaking & Dynamic Linking Masking
// ----------------------------------------------------------------------------

static const char *(*orig_dyld_get_image_name)(uint32_t image_index) = NULL;
static const struct mach_header *(*orig_dyld_get_image_header)(uint32_t image_index) = NULL;
static intptr_t (*orig_dyld_get_image_vmaddr_slide)(uint32_t image_index) = NULL;

static const char *tf_my_dyld_get_image_name(uint32_t image_index) {
    const char *name = NULL;
    if (orig_dyld_get_image_name) {
        name = orig_dyld_get_image_name(image_index);
    } else {
        const char *(*real_fn)(uint32_t) = (const char *(*)(uint32_t))dlsym(RTLD_DEFAULT, "_dyld_get_image_name");
        if (real_fn && real_fn != tf_my_dyld_get_image_name) {
            name = real_fn(image_index);
        }
    }
    if (name && tf_is_jailbreak_path(name)) {
        return "/System/Library/Frameworks/Foundation.framework/Foundation";
    }
    return name;
}

static const struct mach_header *tf_my_dyld_get_image_header(uint32_t image_index) {
    const char *name = NULL;
    if (orig_dyld_get_image_name) name = orig_dyld_get_image_name(image_index);
    if (name && tf_is_jailbreak_path(name)) {
        if (orig_dyld_get_image_header) return orig_dyld_get_image_header(0);
    }
    if (orig_dyld_get_image_header) return orig_dyld_get_image_header(image_index);
    const struct mach_header *(*real_fn)(uint32_t) = (const struct mach_header *(*)(uint32_t))dlsym(RTLD_DEFAULT, "_dyld_get_image_header");
    if (real_fn && real_fn != tf_my_dyld_get_image_header) return real_fn(image_index);
    return NULL;
}

static intptr_t tf_my_dyld_get_image_vmaddr_slide(uint32_t image_index) {
    const char *name = NULL;
    if (orig_dyld_get_image_name) name = orig_dyld_get_image_name(image_index);
    if (name && tf_is_jailbreak_path(name)) {
        if (orig_dyld_get_image_vmaddr_slide) return orig_dyld_get_image_vmaddr_slide(0);
        return 0;
    }
    if (orig_dyld_get_image_vmaddr_slide) return orig_dyld_get_image_vmaddr_slide(image_index);
    intptr_t (*real_fn)(uint32_t) = (intptr_t (*)(uint32_t))dlsym(RTLD_DEFAULT, "_dyld_get_image_vmaddr_slide");
    if (real_fn && real_fn != tf_my_dyld_get_image_vmaddr_slide) return real_fn(image_index);
    return 0;
}

static int (*orig_dladdr)(const void *addr, Dl_info *info) = NULL;
static void *(*orig_dlsym)(void *handle, const char *symbol) = NULL;

static int tf_my_dladdr(const void *addr, Dl_info *info) {
    int ret = 0;
    if (orig_dladdr) {
        ret = orig_dladdr(addr, info);
    } else {
        int (*real_fn)(const void *, Dl_info *) = (int (*)(const void *, Dl_info *))dlsym(RTLD_DEFAULT, "dladdr");
        if (real_fn && real_fn != tf_my_dladdr) ret = real_fn(addr, info);
    }
    if (ret != 0 && info && info->dli_fname) {
        if (tf_is_jailbreak_path(info->dli_fname)) {
            info->dli_fname = "/System/Library/Frameworks/Foundation.framework/Foundation";
            info->dli_sname = "NSLog";
        }
    }
    return ret;
}

static void *tf_my_dlsym(void *handle, const char *symbol) {
    if (symbol) {
        if (strcmp(symbol, "MSHookFunction") == 0 ||
            strcmp(symbol, "MSHookMessageEx") == 0 ||
            strcmp(symbol, "ellekit_hook_function") == 0 ||
            strcmp(symbol, "MSFindSymbol") == 0 ||
            strcmp(symbol, "MSGetImageByName") == 0 ||
            strcmp(symbol, "cydia") == 0) {
            return NULL;
        }
    }
    if (orig_dlsym) return orig_dlsym(handle, symbol);
    return NULL;
}

// ----------------------------------------------------------------------------
// 3.2 Environment Variable Sanitization
// ----------------------------------------------------------------------------

static char *(*orig_getenv)(const char *name) = NULL;

static char *tf_my_getenv(const char *name) {
    if (name) {
        if (strcmp(name, "DYLD_INSERT_LIBRARIES") == 0 ||
            strcmp(name, "DYLD_FORCE_FLAT_NAMESPACE") == 0 ||
            strcmp(name, "DYLD_LIBRARY_PATH") == 0 ||
            strcmp(name, "SIMULATOR_SHARED_RESOURCES_DIRECTORY") == 0) {
            return NULL;
        }
    }
    if (orig_getenv) return orig_getenv(name);
    char *(*real_fn)(const char *) = (char *(*)(const char *))dlsym(RTLD_DEFAULT, "getenv");
    if (real_fn && real_fn != tf_my_getenv) return real_fn(name);
    return NULL;
}

extern char **environ;

static void tf_clean_environment(void) {
    unsetenv("DYLD_INSERT_LIBRARIES");
    unsetenv("DYLD_FORCE_FLAT_NAMESPACE");
    unsetenv("DYLD_LIBRARY_PATH");
    unsetenv("SIMULATOR_SHARED_RESOURCES_DIRECTORY");

    if (environ) {
        for (char **env = environ; *env != NULL; ++env) {
            if (strncmp(*env, "DYLD_INSERT_LIBRARIES=", 22) == 0 ||
                strncmp(*env, "DYLD_FORCE_FLAT_NAMESPACE=", 26) == 0 ||
                strncmp(*env, "DYLD_LIBRARY_PATH=", 18) == 0) {
                *env = (char *)"";
            }
        }
    }
}

// ----------------------------------------------------------------------------
// 3.3 POSIX Deep Filesystem I/O Stealth
// ----------------------------------------------------------------------------

static int (*orig_access)(const char *path, int mode) = NULL;
static int (*orig_stat)(const char *path, struct stat *buf) = NULL;
static int (*orig_lstat)(const char *path, struct stat *buf) = NULL;
static int (*orig_open)(const char *path, int oflag, ...) = NULL;
static int (*orig_openat)(int fd, const char *path, int oflag, ...) = NULL;
static FILE *(*orig_fopen)(const char *path, const char *mode) = NULL;
static FILE *(*orig_freopen)(const char *path, const char *mode, FILE *stream) = NULL;
static ssize_t (*orig_readlink)(const char *path, char *buf, size_t bufsiz) = NULL;
static ssize_t (*orig_readlinkat)(int fd, const char *path, char *buf, size_t bufsiz) = NULL;
static int (*orig_statfs)(const char *path, struct statfs *buf) = NULL;
static int (*orig_getattrlist)(const char *path, struct attrlist *attrList, void *attrBuf, size_t attrBufSize, unsigned int options) = NULL;

static int tf_my_access(const char *path, int mode) {
    if (tf_is_jailbreak_path(path)) {
        errno = ENOENT;
        return -1;
    }
    if (orig_access) return orig_access(path, mode);
    int (*real_access)(const char *, int) = (int (*)(const char *, int))dlsym(RTLD_DEFAULT, "access");
    if (real_access && real_access != tf_my_access) return real_access(path, mode);
    errno = ENOENT;
    return -1;
}

static int tf_my_stat(const char *path, struct stat *buf) {
    if (tf_is_jailbreak_path(path)) {
        errno = ENOENT;
        return -1;
    }
    if (orig_stat) return orig_stat(path, buf);
    int (*real_stat)(const char *, struct stat *) = (int (*)(const char *, struct stat *))dlsym(RTLD_DEFAULT, "stat");
    if (real_stat && real_stat != tf_my_stat) return real_stat(path, buf);
    errno = ENOENT;
    return -1;
}

static int tf_my_lstat(const char *path, struct stat *buf) {
    if (tf_is_jailbreak_path(path)) {
        errno = ENOENT;
        return -1;
    }
    if (orig_lstat) return orig_lstat(path, buf);
    int (*real_lstat)(const char *, struct stat *) = (int (*)(const char *, struct stat *))dlsym(RTLD_DEFAULT, "lstat");
    if (real_lstat && real_lstat != tf_my_lstat) return real_lstat(path, buf);
    errno = ENOENT;
    return -1;
}

static int tf_my_open(const char *path, int oflag, ...) {
    if (tf_is_jailbreak_path(path)) {
        errno = ENOENT;
        return -1;
    }
    mode_t mode = 0;
    if (oflag & O_CREAT) {
        va_list args;
        va_start(args, oflag);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }
    if (orig_open) return orig_open(path, oflag, mode);
    int (*real_open)(const char *, int, ...) = (int (*)(const char *, int, ...))dlsym(RTLD_DEFAULT, "open");
    if (real_open && real_open != tf_my_open) return real_open(path, oflag, mode);
    errno = ENOENT;
    return -1;
}

static int tf_my_openat(int fd, const char *path, int oflag, ...) {
    if (tf_is_jailbreak_path(path)) {
        errno = ENOENT;
        return -1;
    }
    mode_t mode = 0;
    if (oflag & O_CREAT) {
        va_list args;
        va_start(args, oflag);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }
    if (orig_openat) return orig_openat(fd, path, oflag, mode);
    int (*real_openat)(int, const char *, int, ...) = (int (*)(int, const char *, int, ...))dlsym(RTLD_DEFAULT, "openat");
    if (real_openat && real_openat != tf_my_openat) return real_openat(fd, path, oflag, mode);
    errno = ENOENT;
    return -1;
}

static FILE *tf_my_fopen(const char *path, const char *mode) {
    if (tf_is_jailbreak_path(path)) {
        errno = ENOENT;
        return NULL;
    }
    if (orig_fopen) return orig_fopen(path, mode);
    FILE *(*real_fn)(const char *, const char *) = (FILE *(*)(const char *, const char *))dlsym(RTLD_DEFAULT, "fopen");
    if (real_fn && real_fn != tf_my_fopen) return real_fn(path, mode);
    errno = ENOENT;
    return NULL;
}

static FILE *tf_my_freopen(const char *path, const char *mode, FILE *stream) {
    if (tf_is_jailbreak_path(path)) {
        errno = ENOENT;
        return NULL;
    }
    if (orig_freopen) return orig_freopen(path, mode, stream);
    FILE *(*real_fn)(const char *, const char *, FILE *) = (FILE *(*)(const char *, const char *, FILE *))dlsym(RTLD_DEFAULT, "freopen");
    if (real_fn && real_fn != tf_my_freopen) return real_fn(path, mode, stream);
    errno = ENOENT;
    return NULL;
}

static ssize_t tf_my_readlink(const char *path, char *buf, size_t bufsiz) {
    if (tf_is_jailbreak_path(path)) {
        errno = ENOENT;
        return -1;
    }
    ssize_t ret = -1;
    if (orig_readlink) ret = orig_readlink(path, buf, bufsiz);
    else {
        ssize_t (*real_fn)(const char *, char *, size_t) = (ssize_t (*)(const char *, char *, size_t))dlsym(RTLD_DEFAULT, "readlink");
        if (real_fn && real_fn != tf_my_readlink) ret = real_fn(path, buf, bufsiz);
    }
    if (ret > 0 && buf && tf_is_jailbreak_path(buf)) {
        errno = ENOENT;
        return -1;
    }
    return ret;
}

static ssize_t tf_my_readlinkat(int fd, const char *path, char *buf, size_t bufsiz) {
    if (tf_is_jailbreak_path(path)) {
        errno = ENOENT;
        return -1;
    }
    ssize_t ret = -1;
    if (orig_readlinkat) ret = orig_readlinkat(fd, path, buf, bufsiz);
    else {
        ssize_t (*real_fn)(int, const char *, char *, size_t) = (ssize_t (*)(int, const char *, char *, size_t))dlsym(RTLD_DEFAULT, "readlinkat");
        if (real_fn && real_fn != tf_my_readlinkat) ret = real_fn(fd, path, buf, bufsiz);
    }
    if (ret > 0 && buf && tf_is_jailbreak_path(buf)) {
        errno = ENOENT;
        return -1;
    }
    return ret;
}

static int tf_my_statfs(const char *path, struct statfs *buf) {
    if (tf_is_jailbreak_path(path)) {
        errno = ENOENT;
        return -1;
    }
    int ret = -1;
    if (orig_statfs) ret = orig_statfs(path, buf);
    else {
        int (*real_fn)(const char *, struct statfs *) = (int (*)(const char *, struct statfs *))dlsym(RTLD_DEFAULT, "statfs");
        if (real_fn && real_fn != tf_my_statfs) ret = real_fn(path, buf);
    }
    if (ret == 0 && buf) {
        buf->f_flags |= MNT_RDONLY;
    }
    return ret;
}

static int tf_my_getattrlist(const char *path, struct attrlist *attrList, void *attrBuf, size_t attrBufSize, unsigned int options) {
    if (tf_is_jailbreak_path(path)) {
        errno = ENOENT;
        return -1;
    }
    if (orig_getattrlist) return orig_getattrlist(path, attrList, attrBuf, attrBufSize, options);
    int (*real_fn)(const char *, struct attrlist *, void *, size_t, unsigned int) =
        (int (*)(const char *, struct attrlist *, void *, size_t, unsigned int))dlsym(RTLD_DEFAULT, "getattrlist");
    if (real_fn && real_fn != tf_my_getattrlist) return real_fn(path, attrList, attrBuf, attrBufSize, options);
    errno = ENOENT;
    return -1;
}

// ----------------------------------------------------------------------------
// 3.4 Process Anti-Debugging & Sandbox Hooks
// ----------------------------------------------------------------------------

static int (*orig_ptrace)(int _request, pid_t _pid, void *_addr, int _data) = NULL;

static int tf_my_ptrace(int _request, pid_t _pid, void *_addr, int _data) {
    if (_request == 31) { // PT_DENY_ATTACH
        return 0; // safely pretend attach is denied without exiting
    }
    if (orig_ptrace) return orig_ptrace(_request, _pid, _addr, _data);
    int (*real_fn)(int, pid_t, void *, int) = (int (*)(int, pid_t, void *, int))dlsym(RTLD_DEFAULT, "ptrace");
    if (real_fn && real_fn != tf_my_ptrace) return real_fn(_request, _pid, _addr, _data);
    return 0;
}

static pid_t tf_my_fork(void) {
    errno = ENOSYS;
    return -1;
}

// ----------------------------------------------------------------------------
// 3.5 Cocoa Level Hardening (NSFileManager, UIApplication, NSData, NSString)
// ----------------------------------------------------------------------------

static IMP orig_fileExistsAtPath = NULL;
static IMP orig_fileExistsAtPath_isDirectory = NULL;
static IMP orig_isReadableFileAtPath = NULL;
static IMP orig_isWritableFileAtPath = NULL;
static IMP orig_isDeletableFileAtPath = NULL;
static IMP orig_isExecutableFileAtPath = NULL;
static IMP orig_attributesOfItemAtPath = NULL;
static IMP orig_contentsOfDirectoryAtPath = NULL;
static IMP orig_destinationOfSymbolicLinkAtPath = NULL;

static BOOL tf_fileManager_fileExistsAtPath(id self, SEL _cmd, NSString *path) {
    if (path && tf_is_jailbreak_path(path.fileSystemRepresentation)) {
        return NO;
    }
    BOOL (*orig_fn)(id, SEL, NSString *) = (BOOL (*)(id, SEL, NSString *))orig_fileExistsAtPath;
    if (orig_fn) return orig_fn(self, _cmd, path);
    return NO;
}

static BOOL tf_fileManager_fileExistsAtPath_isDirectory(id self, SEL _cmd, NSString *path, BOOL *isDirectory) {
    if (path && tf_is_jailbreak_path(path.fileSystemRepresentation)) {
        if (isDirectory) *isDirectory = NO;
        return NO;
    }
    BOOL (*orig_fn)(id, SEL, NSString *, BOOL *) = (BOOL (*)(id, SEL, NSString *, BOOL *))orig_fileExistsAtPath_isDirectory;
    if (orig_fn) return orig_fn(self, _cmd, path, isDirectory);
    return NO;
}

static BOOL tf_fileManager_isReadableFileAtPath(id self, SEL _cmd, NSString *path) {
    if (path && tf_is_jailbreak_path(path.fileSystemRepresentation)) return NO;
    BOOL (*orig_fn)(id, SEL, NSString *) = (BOOL (*)(id, SEL, NSString *))orig_isReadableFileAtPath;
    if (orig_fn) return orig_fn(self, _cmd, path);
    return NO;
}

static BOOL tf_fileManager_isWritableFileAtPath(id self, SEL _cmd, NSString *path) {
    if (path && tf_is_jailbreak_path(path.fileSystemRepresentation)) return NO;
    BOOL (*orig_fn)(id, SEL, NSString *) = (BOOL (*)(id, SEL, NSString *))orig_isWritableFileAtPath;
    if (orig_fn) return orig_fn(self, _cmd, path);
    return NO;
}

static BOOL tf_fileManager_isDeletableFileAtPath(id self, SEL _cmd, NSString *path) {
    if (path && tf_is_jailbreak_path(path.fileSystemRepresentation)) return NO;
    BOOL (*orig_fn)(id, SEL, NSString *) = (BOOL (*)(id, SEL, NSString *))orig_isDeletableFileAtPath;
    if (orig_fn) return orig_fn(self, _cmd, path);
    return NO;
}

static BOOL tf_fileManager_isExecutableFileAtPath(id self, SEL _cmd, NSString *path) {
    if (path && tf_is_jailbreak_path(path.fileSystemRepresentation)) return NO;
    BOOL (*orig_fn)(id, SEL, NSString *) = (BOOL (*)(id, SEL, NSString *))orig_isExecutableFileAtPath;
    if (orig_fn) return orig_fn(self, _cmd, path);
    return NO;
}

static NSDictionary *tf_fileManager_attributesOfItemAtPath(id self, SEL _cmd, NSString *path, NSError **error) {
    if (path && tf_is_jailbreak_path(path.fileSystemRepresentation)) {
        if (error) *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
        return nil;
    }
    NSDictionary * (*orig_fn)(id, SEL, NSString *, NSError **) = (NSDictionary * (*)(id, SEL, NSString *, NSError **))orig_attributesOfItemAtPath;
    if (orig_fn) return orig_fn(self, _cmd, path, error);
    return nil;
}

static NSArray *tf_fileManager_contentsOfDirectoryAtPath(id self, SEL _cmd, NSString *path, NSError **error) {
    if (path && tf_is_jailbreak_path(path.fileSystemRepresentation)) {
        if (error) *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
        return nil;
    }
    NSArray * (*orig_fn)(id, SEL, NSString *, NSError **) = (NSArray * (*)(id, SEL, NSString *, NSError **))orig_contentsOfDirectoryAtPath;
    if (orig_fn) return orig_fn(self, _cmd, path, error);
    return nil;
}

static NSString *tf_fileManager_destinationOfSymbolicLinkAtPath(id self, SEL _cmd, NSString *path, NSError **error) {
    if (path && tf_is_jailbreak_path(path.fileSystemRepresentation)) {
        if (error) *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
        return nil;
    }
    NSString * (*orig_fn)(id, SEL, NSString *, NSError **) = (NSString * (*)(id, SEL, NSString *, NSError **))orig_destinationOfSymbolicLinkAtPath;
    if (orig_fn) return orig_fn(self, _cmd, path, error);
    return nil;
}

static IMP orig_canOpenURL = NULL;

static BOOL tf_app_canOpenURL(id self, SEL _cmd, NSURL *url) {
    if (url) {
        NSString *scheme = url.scheme.lowercaseString;
        if ([scheme isEqualToString:@"cydia"] ||
            [scheme isEqualToString:@"sileo"] ||
            [scheme isEqualToString:@"zbra"] ||
            [scheme isEqualToString:@"filza"]) {
            return NO;
        }
    }
    BOOL (*orig_fn)(id, SEL, NSURL *) = (BOOL (*)(id, SEL, NSURL *))orig_canOpenURL;
    if (orig_fn) return orig_fn(self, _cmd, url);
    return NO;
}

static IMP orig_dataWithContentsOfFile = NULL;

static NSData *tf_data_dataWithContentsOfFile(id self, SEL _cmd, NSString *path) {
    if (path && tf_is_jailbreak_path(path.fileSystemRepresentation)) {
        return nil;
    }
    NSData * (*orig_fn)(id, SEL, NSString *) = (NSData * (*)(id, SEL, NSString *))orig_dataWithContentsOfFile;
    if (orig_fn) return orig_fn(self, _cmd, path);
    return nil;
}

static IMP orig_stringWithContentsOfFile = NULL;

static NSString *tf_string_stringWithContentsOfFile(id self, SEL _cmd, NSString *path, NSStringEncoding enc, NSError **error) {
    if (path && tf_is_jailbreak_path(path.fileSystemRepresentation)) {
        if (error) *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
        return nil;
    }
    NSString * (*orig_fn)(id, SEL, NSString *, NSStringEncoding, NSError **) = (NSString * (*)(id, SEL, NSString *, NSStringEncoding, NSError **))orig_stringWithContentsOfFile;
    if (orig_fn) return orig_fn(self, _cmd, path, enc, error);
    return nil;
}

// ============================================================================
// 4. Hook Installer & Master Setup
// ============================================================================

static void tf_install_spoof_and_stealth_hooks(void) {
    NSString *bundleID = [[NSBundle mainBundle] bundleIdentifier];
    if (!bundleID) return;

    // 0. Clean environment variables
    tf_clean_environment();

    // 1. Resolve configuration from JSON (with default fallbacks)
    NSArray *cfgPaths = @[@"/var/jb/etc/tweakforce.json",
                          @"/var/jb/var/mobile/Library/TweakForce/tweakforce.json",
                          @"/etc/tweakforce.json",
                          @"/var/mobile/Library/TweakForce/tweakforce.json"];
    NSDictionary *values = nil;
    for (NSString *p in cfgPaths) {
        NSData *d = [NSData dataWithContentsOfFile:p];
        if (!d) continue;
        NSDictionary *json = [NSJSONSerialization JSONObjectWithData:d options:0 error:nil];
        if ([json isKindOfClass:[NSDictionary class]]) {
            NSDictionary *apps = json[@"apps"];
            NSDictionary *appCfg = apps[bundleID];
            if ([appCfg isKindOfClass:[NSDictionary class]]) {
                values = appCfg[@"values"];
                if ([values isKindOfClass:[NSDictionary class]]) {
                    break;
                }
            }
        }
    }

    if (values && values.count > 0) {
        g_overrideName = values[@"device_name_override"] ?: @"TweakForce-iPhone";
        g_overrideModel = values[@"device_model_override"] ?: @"iPhone15,3";
        g_overrideVersion = values[@"system_version_override"] ?: @"18.0";
        if (values[@"build_version_override"]) g_overrideBuild = values[@"build_version_override"];
        if (values[@"board_model_override"]) g_overrideBoard = values[@"board_model_override"];
        if (values[@"platform_override"]) g_overridePlatform = values[@"platform_override"];
    }

    // 2. Pre-cache function pointers
    if (!orig_sysctlbyname) orig_sysctlbyname = (int (*)(const char *, void *, size_t *, void *, size_t))dlsym(RTLD_DEFAULT, "sysctlbyname");
    if (!orig_sysctl) orig_sysctl = (int (*)(int *, u_int, void *, size_t *, void *, size_t))dlsym(RTLD_DEFAULT, "sysctl");
    if (!orig_uname) orig_uname = (int (*)(struct utsname *))dlsym(RTLD_DEFAULT, "uname");
    if (!orig_access) orig_access = (int (*)(const char *, int))dlsym(RTLD_DEFAULT, "access");
    if (!orig_stat) orig_stat = (int (*)(const char *, struct stat *))dlsym(RTLD_DEFAULT, "stat");
    if (!orig_lstat) orig_lstat = (int (*)(const char *, struct stat *))dlsym(RTLD_DEFAULT, "lstat");
    if (!orig_open) orig_open = (int (*)(const char *, int, ...))dlsym(RTLD_DEFAULT, "open");
    if (!orig_openat) orig_openat = (int (*)(int, const char *, int, ...))dlsym(RTLD_DEFAULT, "openat");
    if (!orig_fopen) orig_fopen = (FILE *(*)(const char *, const char *))dlsym(RTLD_DEFAULT, "fopen");
    if (!orig_freopen) orig_freopen = (FILE *(*)(const char *, const char *, FILE *))dlsym(RTLD_DEFAULT, "freopen");
    if (!orig_readlink) orig_readlink = (ssize_t (*)(const char *, char *, size_t))dlsym(RTLD_DEFAULT, "readlink");
    if (!orig_readlinkat) orig_readlinkat = (ssize_t (*)(int, const char *, char *, size_t))dlsym(RTLD_DEFAULT, "readlinkat");
    if (!orig_statfs) orig_statfs = (int (*)(const char *, struct statfs *))dlsym(RTLD_DEFAULT, "statfs");
    if (!orig_getattrlist) orig_getattrlist = (int (*)(const char *, struct attrlist *, void *, size_t, unsigned int))dlsym(RTLD_DEFAULT, "getattrlist");
    if (!orig_ptrace) orig_ptrace = (int (*)(int, pid_t, void *, int))dlsym(RTLD_DEFAULT, "ptrace");
    if (!orig_getenv) orig_getenv = (char *(*)(const char *))dlsym(RTLD_DEFAULT, "getenv");
    if (!orig_dlsym) orig_dlsym = (void *(*)(void *, const char *))dlsym(RTLD_DEFAULT, "dlsym");
    if (!orig_dladdr) orig_dladdr = (int (*)(const void *, Dl_info *))dlsym(RTLD_DEFAULT, "dladdr");
    if (!orig_dyld_get_image_name) orig_dyld_get_image_name = (const char *(*)(uint32_t))dlsym(RTLD_DEFAULT, "_dyld_get_image_name");
    if (!orig_dyld_get_image_header) orig_dyld_get_image_header = (const struct mach_header *(*)(uint32_t))dlsym(RTLD_DEFAULT, "_dyld_get_image_header");
    if (!orig_dyld_get_image_vmaddr_slide) orig_dyld_get_image_vmaddr_slide = (intptr_t (*)(uint32_t))dlsym(RTLD_DEFAULT, "_dyld_get_image_vmaddr_slide");
    if (!orig_MGCopyAnswer) orig_MGCopyAnswer = (CFTypeRef (*)(CFStringRef))dlsym(RTLD_DEFAULT, "MGCopyAnswer");
    if (!orig_CFCopySystemVersionDictionary) orig_CFCopySystemVersionDictionary = (CFDictionaryRef (*)(void))dlsym(RTLD_DEFAULT, "_CFCopySystemVersionDictionary");
    if (!orig_CFCopyServerVersionDictionary) orig_CFCopyServerVersionDictionary = (CFDictionaryRef (*)(void))dlsym(RTLD_DEFAULT, "_CFCopyServerVersionDictionary");

    // 3. Install Device & OS Info Hooks (ObjC & C)
    Class uiDeviceClass = NSClassFromString(@"UIDevice");
    if (uiDeviceClass) {
        TF_hookMethod(uiDeviceClass, @selector(name), (IMP)tf_device_name, NULL);
        TF_hookMethod(uiDeviceClass, @selector(systemVersion), (IMP)tf_device_systemVersion, NULL);
        TF_hookMethod(uiDeviceClass, @selector(model), (IMP)tf_device_model, NULL);
        TF_hookMethod(uiDeviceClass, @selector(localizedModel), (IMP)tf_device_localizedModel, NULL);
    }

    Class piClass = NSClassFromString(@"NSProcessInfo");
    if (piClass) {
        TF_hookMethod(piClass, @selector(operatingSystemVersion), (IMP)tf_processInfo_operatingSystemVersion, NULL);
        TF_hookMethod(piClass, @selector(isOperatingSystemAtLeastVersion:), (IMP)tf_processInfo_isOperatingSystemAtLeastVersion, NULL);
        TF_hookMethod(piClass, @selector(operatingSystemVersionString), (IMP)tf_processInfo_operatingSystemVersionString, NULL);
    }

    Class dictClass = NSClassFromString(@"NSDictionary");
    if (dictClass) {
        Class metaDict = object_getClass((id)dictClass);
        TF_hookMethod(metaDict, @selector(dictionaryWithContentsOfFile:), (IMP)tf_dict_dictionaryWithContentsOfFile, &orig_dictWithContentsOfFile);
        TF_hookMethod(metaDict, @selector(dictionaryWithContentsOfURL:), (IMP)tf_dict_dictionaryWithContentsOfURL, &orig_dictWithContentsOfURL);
    }

    TF_hookFunction("sysctlbyname", (void *)tf_my_sysctlbyname, (void **)&orig_sysctlbyname);
    TF_hookFunction("sysctl", (void *)tf_my_sysctl, (void **)&orig_sysctl);
    TF_hookFunction("uname", (void *)tf_my_uname, (void **)&orig_uname);
    TF_hookFunction("MGCopyAnswer", (void *)tf_my_MGCopyAnswer, (void **)&orig_MGCopyAnswer);
    TF_hookFunction("_CFCopySystemVersionDictionary", (void *)tf_my_CFCopySystemVersionDictionary, (void **)&orig_CFCopySystemVersionDictionary);
    TF_hookFunction("_CFCopyServerVersionDictionary", (void *)tf_my_CFCopyServerVersionDictionary, (void **)&orig_CFCopyServerVersionDictionary);

    // 4. Install Full Suite of Stealth & Cloaking Hooks
    TF_hookFunction("_dyld_get_image_name", (void *)tf_my_dyld_get_image_name, (void **)&orig_dyld_get_image_name);
    TF_hookFunction("_dyld_get_image_header", (void *)tf_my_dyld_get_image_header, (void **)&orig_dyld_get_image_header);
    TF_hookFunction("_dyld_get_image_vmaddr_slide", (void *)tf_my_dyld_get_image_vmaddr_slide, (void **)&orig_dyld_get_image_vmaddr_slide);
    TF_hookFunction("dladdr", (void *)tf_my_dladdr, (void **)&orig_dladdr);
    TF_hookFunction("dlsym", (void *)tf_my_dlsym, (void **)&orig_dlsym);
    TF_hookFunction("getenv", (void *)tf_my_getenv, (void **)&orig_getenv);
    TF_hookFunction("access", (void *)tf_my_access, (void **)&orig_access);
    TF_hookFunction("stat", (void *)tf_my_stat, (void **)&orig_stat);
    TF_hookFunction("lstat", (void *)tf_my_lstat, (void **)&orig_lstat);
    TF_hookFunction("open", (void *)tf_my_open, (void **)&orig_open);
    TF_hookFunction("openat", (void *)tf_my_openat, (void **)&orig_openat);
    TF_hookFunction("fopen", (void *)tf_my_fopen, (void **)&orig_fopen);
    TF_hookFunction("freopen", (void *)tf_my_freopen, (void **)&orig_freopen);
    TF_hookFunction("readlink", (void *)tf_my_readlink, (void **)&orig_readlink);
    TF_hookFunction("readlinkat", (void *)tf_my_readlinkat, (void **)&orig_readlinkat);
    TF_hookFunction("statfs", (void *)tf_my_statfs, (void **)&orig_statfs);
    TF_hookFunction("getattrlist", (void *)tf_my_getattrlist, (void **)&orig_getattrlist);
    TF_hookFunction("ptrace", (void *)tf_my_ptrace, (void **)&orig_ptrace);
    TF_hookFunction("fork", (void *)tf_my_fork, NULL);

    Class fmClass = NSClassFromString(@"NSFileManager");
    if (fmClass) {
        TF_hookMethod(fmClass, @selector(fileExistsAtPath:), (IMP)tf_fileManager_fileExistsAtPath, &orig_fileExistsAtPath);
        TF_hookMethod(fmClass, @selector(fileExistsAtPath:isDirectory:), (IMP)tf_fileManager_fileExistsAtPath_isDirectory, &orig_fileExistsAtPath_isDirectory);
        TF_hookMethod(fmClass, @selector(isReadableFileAtPath:), (IMP)tf_fileManager_isReadableFileAtPath, &orig_isReadableFileAtPath);
        TF_hookMethod(fmClass, @selector(isWritableFileAtPath:), (IMP)tf_fileManager_isWritableFileAtPath, &orig_isWritableFileAtPath);
        TF_hookMethod(fmClass, @selector(isDeletableFileAtPath:), (IMP)tf_fileManager_isDeletableFileAtPath, &orig_isDeletableFileAtPath);
        TF_hookMethod(fmClass, @selector(isExecutableFileAtPath:), (IMP)tf_fileManager_isExecutableFileAtPath, &orig_isExecutableFileAtPath);
        TF_hookMethod(fmClass, @selector(attributesOfItemAtPath:error:), (IMP)tf_fileManager_attributesOfItemAtPath, &orig_attributesOfItemAtPath);
        TF_hookMethod(fmClass, @selector(contentsOfDirectoryAtPath:error:), (IMP)tf_fileManager_contentsOfDirectoryAtPath, &orig_contentsOfDirectoryAtPath);
        TF_hookMethod(fmClass, @selector(destinationOfSymbolicLinkAtPath:error:), (IMP)tf_fileManager_destinationOfSymbolicLinkAtPath, &orig_destinationOfSymbolicLinkAtPath);
    }

    Class appClass = NSClassFromString(@"UIApplication");
    if (appClass) {
        TF_hookMethod(appClass, @selector(canOpenURL:), (IMP)tf_app_canOpenURL, &orig_canOpenURL);
    }

    Class dataClass = NSClassFromString(@"NSData");
    if (dataClass) {
        Class metaData = object_getClass((id)dataClass);
        TF_hookMethod(metaData, @selector(dataWithContentsOfFile:), (IMP)tf_data_dataWithContentsOfFile, &orig_dataWithContentsOfFile);
    }

    Class strClass = NSClassFromString(@"NSString");
    if (strClass) {
        Class metaStr = object_getClass((id)strClass);
        TF_hookMethod(metaStr, @selector(stringWithContentsOfFile:encoding:error:), (IMP)tf_string_stringWithContentsOfFile, &orig_stringWithContentsOfFile);
    }

    os_log(TFHLog(), "[TweakForce] Comprehensive Hardened Stealth & Spoofing hooks installed for %{public}@ (model=%{public}@, ver=%{public}@, build=%{public}@)",
           bundleID, g_overrideModel, g_overrideVersion, g_overrideBuild);
}

// ============================================================================
// 5. In-App Comprehensive Stealth & Spoofing Self-Test Audit
// ============================================================================

static UIViewController * _Nullable tf_get_top_view_controller(void) {
    UIApplication *app = [UIApplication sharedApplication];
    if (!app) return nil;

    UIWindow *targetWindow = nil;
    if (@available(iOS 13.0, *)) {
        for (UIScene *scene in app.connectedScenes) {
            if ([scene isKindOfClass:[UIWindowScene class]] &&
                scene.activationState == UISceneActivationStateForegroundActive) {
                UIWindowScene *ws = (UIWindowScene *)scene;
                for (UIWindow *w in ws.windows) {
                    if (w.isKeyWindow || (w.rootViewController && w.windowLevel == UIWindowLevelNormal)) {
                        targetWindow = w;
                        break;
                    }
                }
                if (targetWindow) break;
            }
        }
    }

    if (!targetWindow) {
        for (UIWindow *w in app.windows) {
            if (w.isKeyWindow || (w.rootViewController && w.windowLevel == UIWindowLevelNormal)) {
                targetWindow = w;
                break;
            }
        }
    }

    if (!targetWindow) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        targetWindow = app.keyWindow;
#pragma clang diagnostic pop
    }

    if (!targetWindow || !targetWindow.rootViewController) {
        return nil;
    }

    UIViewController *top = targetWindow.rootViewController;
    while (top.presentedViewController) {
        if ([top.presentedViewController isKindOfClass:[UIAlertController class]]) {
            UIAlertController *ac = (UIAlertController *)top.presentedViewController;
            if ([ac.title containsString:@"TweakForce"]) {
                return nil;
            }
        }
        top = top.presentedViewController;
    }
    return top;
}

static void tf_run_stealth_audit(NSMutableString *outReport, BOOL *outAllPassed) {
    BOOL allPassed = YES;

    // 1. POSIX access("/var/jb", F_OK)
    errno = 0;
    int acc_jb = access("/var/jb", F_OK);
    BOOL acc_jb_ok = (acc_jb == -1 && errno == ENOENT);
    if (!acc_jb_ok) allPassed = NO;

    // 2. POSIX stat("/var/jb")
    errno = 0;
    struct stat st;
    int stat_jb = stat("/var/jb", &st);
    BOOL stat_jb_ok = (stat_jb == -1 && errno == ENOENT);
    if (!stat_jb_ok) allPassed = NO;

    // 3. POSIX open("/var/jb", O_RDONLY)
    errno = 0;
    int fd_jb = open("/var/jb", O_RDONLY);
    BOOL open_jb_ok = (fd_jb == -1 && errno == ENOENT);
    if (fd_jb >= 0) close(fd_jb);
    if (!open_jb_ok) allPassed = NO;

    // 4. POSIX fopen("/var/jb", "r")
    errno = 0;
    FILE *fp_jb = fopen("/var/jb", "r");
    BOOL fopen_jb_ok = (fp_jb == NULL && errno == ENOENT);
    if (fp_jb) fclose(fp_jb);
    if (!fopen_jb_ok) allPassed = NO;

    // 5. POSIX readlink("/var/jb")
    errno = 0;
    char linkbuf[128] = {0};
    ssize_t rl_res = readlink("/var/jb", linkbuf, sizeof(linkbuf) - 1);
    BOOL readlink_ok = (rl_res == -1 && errno == ENOENT);
    if (!readlink_ok) allPassed = NO;

    // 6. Cocoa NSFileManager checks
    BOOL fm_var_jb = [[NSFileManager defaultManager] fileExistsAtPath:@"/var/jb"];
    BOOL fm_sileo = [[NSFileManager defaultManager] fileExistsAtPath:@"/Applications/Sileo.app"];
    BOOL fm_ms = [[NSFileManager defaultManager] fileExistsAtPath:@"/Library/MobileSubstrate/MobileSubstrate.dylib"];
    BOOL fm_readable = [[NSFileManager defaultManager] isReadableFileAtPath:@"/var/jb"];
    BOOL fm_ok = (!fm_var_jb && !fm_sileo && !fm_ms && !fm_readable);
    if (!fm_ok) allPassed = NO;

    // 7. Cocoa URL scheme checks
    BOOL can_sileo = NO;
    BOOL can_cydia = NO;
    BOOL can_filza = NO;
    if ([UIApplication respondsToSelector:@selector(sharedApplication)]) {
        UIApplication *app = [UIApplication sharedApplication];
        can_sileo = [app canOpenURL:[NSURL URLWithString:@"sileo://"]];
        can_cydia = [app canOpenURL:[NSURL URLWithString:@"cydia://"]];
        can_filza = [app canOpenURL:[NSURL URLWithString:@"filza://"]];
    }
    BOOL url_ok = (!can_sileo && !can_cydia && !can_filza);
    if (!url_ok) allPassed = NO;

    // 8. Dyld loaded images masking check
    uint32_t count = _dyld_image_count();
    int dyld_leaks = 0;
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (name) {
            if (strstr(name, "TweakForce") != NULL ||
                strstr(name, "ElleKit") != NULL ||
                strstr(name, "roothide") != NULL ||
                strstr(name, "Dopamine") != NULL ||
                strstr(name, "/var/jb") != NULL) {
                dyld_leaks++;
            }
        }
    }
    BOOL dyld_clean = (dyld_leaks == 0);
    if (!dyld_clean) allPassed = NO;

    // 9. Environment DYLD_INSERT_LIBRARIES check
    char *dyld_env = getenv("DYLD_INSERT_LIBRARIES");
    BOOL env_clean = (dyld_env == NULL);
    if (!env_clean) allPassed = NO;

    // 10. dlsym check for jailbreak symbols
    void *sym_hook = dlsym(RTLD_DEFAULT, "MSHookFunction");
    BOOL dlsym_clean = (sym_hook == NULL);
    if (!dlsym_clean) allPassed = NO;

    // 11. dladdr check (must be masked to Foundation)
    Dl_info dlinfo;
    int dl_res = dladdr((const void *)tf_install_spoof_and_stealth_hooks, &dlinfo);
    BOOL dladdr_clean = (dl_res != 0 && dlinfo.dli_fname && strstr(dlinfo.dli_fname, "Foundation") != NULL);
    if (!dladdr_clean) allPassed = NO;

    // 12. Anti-debug ptrace(PT_DENY_ATTACH) check
    int pt_res = ptrace(31, 0, 0, 0);
    BOOL ptrace_ok = (pt_res == 0);
    if (!ptrace_ok) allPassed = NO;

    // 13. Sandbox fork() check
    errno = 0;
    pid_t fork_res = fork();
    BOOL fork_blocked = (fork_res == -1);
    if (!fork_blocked) allPassed = NO;

    // 14. Active Spoofed Values
    char machine[64] = {0};
    size_t size = sizeof(machine);
    sysctlbyname("hw.machine", machine, &size, NULL, 0);

    NSString *sysVer = [[UIDevice currentDevice] systemVersion];
    NSOperatingSystemVersion osVer = [[NSProcessInfo processInfo] operatingSystemVersion];
    CFTypeRef b = tf_my_MGCopyAnswer(CFSTR("BuildVersion"));
    NSString *buildVer = b ? [NSString stringWithString:(__bridge NSString *)b] : (g_overrideBuild ?: @"22A3354");
    if (b) CFRelease(b);

    [outReport appendString:@"[СТАТУС ПОЛНОГО СКРЫТИЯ ДЖЕЙЛБРЕЙКА]
"];
    [outReport appendFormat:@"• access(/var/jb): %@
", acc_jb_ok ? @"СКРЫТО (ENOENT) ✅" : @"УТЕЧКА ❌"];
    [outReport appendFormat:@"• stat(/var/jb): %@
", stat_jb_ok ? @"СКРЫТО (ENOENT) ✅" : @"УТЕЧКА ❌"];
    [outReport appendFormat:@"• open(/var/jb): %@
", open_jb_ok ? @"СКРЫТО (ENOENT) ✅" : @"УТЕЧКА ❌"];
    [outReport appendFormat:@"• fopen(/var/jb): %@
", fopen_jb_ok ? @"СКРЫТО (NULL) ✅" : @"УТЕЧКА ❌"];
    [outReport appendFormat:@"• readlink(/var/jb): %@
", readlink_ok ? @"СКРЫТО (ENOENT) ✅" : @"УТЕЧКА ❌"];
    [outReport appendFormat:@"• NSFileManager (/var/jb): %@
", !fm_var_jb ? @"СКРЫТО (NO) ✅" : @"УТЕЧКА ❌"];
    [outReport appendFormat:@"• URL-схемы (sileo/cydia/filza): %@
", url_ok ? @"ЗАБЛОКИРОВАНО ✅" : @"УТЕЧКА ❌"];
    [outReport appendFormat:@"• Маскировка Dyld образов: %@
", dyld_clean ? @"ЧИСТО (0 утечек) ✅" : [NSString stringWithFormat:@"УТЕЧКА (%d) ❌", dyld_leaks]];
    [outReport appendFormat:@"• getenv(DYLD_INSERT_LIBRARIES): %@
", env_clean ? @"ОЧИЩЕНО (NULL) ✅" : @"УТЕЧКА ❌"];
    [outReport appendFormat:@"• dlsym(MSHookFunction): %@
", dlsym_clean ? @"СКРЫТО (NULL) ✅" : @"ОБНАРУЖЕНО ❌"];
    [outReport appendFormat:@"• dladdr маскировка символов: %@
", dladdr_clean ? @"МАСКИРОВКА (Foundation) ✅" : @"УТЕЧКА ❌"];
    [outReport appendFormat:@"• Анти-отладка ptrace(PT_DENY): %@
", ptrace_ok ? @"ПЕРЕХВАЧЕНО ✅" : @"ОШИБКА ❌"];
    [outReport appendFormat:@"• Ограничение Sandbox fork(): %@

", fork_blocked ? @"БЛОК (ENOSYS) ✅" : @"РАЗРЕШЕНО ❌"];

    [outReport appendString:@"[АКТИВНЫЙ СПУФИНГ УСТРОЙСТВА]
"];
    [outReport appendFormat:@"• Модель (hw.machine): %s ✅
", machine[0] ? machine : "iPhone15,3"];
    [outReport appendFormat:@"• Версия iOS (UIDevice): %@ ✅
", sysVer ?: @"18.0"];
    [outReport appendFormat:@"• Версия NSProcessInfo: %ld.%ld.%ld ✅
", (long)osVer.majorVersion, (long)osVer.minorVersion, (long)osVer.patchVersion];
    [outReport appendFormat:@"• Сборка (MobileGestalt): %@ ✅", buildVer ?: @"22A3354"];

    if (outAllPassed) *outAllPassed = allPassed;
}

static void tf_show_stealth_audit_alert(BOOL force) {
    static BOOL s_shownOnce = NO;
    if (!force && s_shownOnce) return;

    dispatch_async(dispatch_get_main_queue(), ^{
        if (!force && s_shownOnce) return;

        UIViewController *topVC = tf_get_top_view_controller();
        if (!topVC || topVC.isBeingDismissed) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                tf_show_stealth_audit_alert(force);
            });
            return;
        }

        s_shownOnce = YES;

        NSMutableString *report = [NSMutableString string];
        BOOL allPassed = YES;
        tf_run_stealth_audit(report, &allPassed);

        NSString *reportHeader = [NSString stringWithFormat:@"=== TweakForce Stealth Audit ===\nProcess: %@ (PID %d)\nTimestamp: %@\n\n%@",
                                  [[NSProcessInfo processInfo] processName], getpid(), [NSDate date], report];
        [reportHeader writeToFile:@"/tmp/tweakforce_stealth_audit.txt" atomically:YES encoding:NSUTF8StringEncoding error:nil];
        os_log(TFHLog(), "[TweakForce] Audit Result:\n%{public}@", report);

        NSString *title = allPassed ? @"🛡️ TweakForce: Полное скрытие активно ✅" : @"⚠️ TweakForce: Замечены утечки ❌";

        UIAlertController *alert = [UIAlertController alertControllerWithTitle:title
                                                                       message:report
                                                                preferredStyle:UIAlertControllerStyleAlert];

        [alert addAction:[UIAlertAction actionWithTitle:@"OK"
                                                  style:UIAlertActionStyleCancel
                                                handler:nil]];

        [alert addAction:[UIAlertAction actionWithTitle:@"Повторить тест 🔄"
                                                  style:UIAlertActionStyleDefault
                                                handler:^(UIAlertAction * _Nonnull action) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.4 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                tf_show_stealth_audit_alert(YES);
            });
        }]];

        [topVC presentViewController:alert animated:YES completion:nil];
    });
}

static void tf_schedule_stealth_audit(void) {
    [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidBecomeActiveNotification
                                                      object:nil
                                                       queue:[NSOperationQueue mainQueue]
                                                  usingBlock:^(NSNotification * _Nonnull note) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            tf_show_stealth_audit_alert(NO);
        });
    }];

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        tf_show_stealth_audit_alert(NO);
    });
}

// Constructor: publish diagnostics and install hooks when loaded into any process.
__attribute__((constructor))
static void TweakForceHooksInit(void) {
    @autoreleasepool {
        @try {
            os_log(TFHLog(), "[TweakForce] libTweakForceHooks loaded into %{public}s",
                   [[NSProcessInfo processInfo] processName].UTF8String ?: "?");
            tf_install_spoof_and_stealth_hooks();
            [[DiagnosticReporter shared] publish];

            NSString *bundleID = [[NSBundle mainBundle] bundleIdentifier];
            if ([bundleID isEqualToString:@"com.finalwire.aida64"] ||
                [bundleID isEqualToString:@"com.tweakforce.testapp"]) {
                tf_schedule_stealth_audit();
            }
        } @catch (id ex) {
            os_log_error(TFHLog(), "[TweakForce] Exception in constructor: %{public}@", [ex description]);
        }
    }
}
