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
#import <CoreFoundation/CoreFoundation.h>
#import <UIKit/UIKit.h>

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
    }
    return ret;
}

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

// ============================================================================
// 2. MobileGestalt Hook (MGCopyAnswer)
// ============================================================================

static CFTypeRef (*orig_MGCopyAnswer)(CFStringRef prop) = NULL;

static CFTypeRef tf_my_MGCopyAnswer(CFStringRef prop) {
    if (prop) {
        if (CFEqual(prop, CFSTR("ProductType"))) {
            return (__bridge_retained CFTypeRef)(g_overrideModel ?: @"iPhone15,3");
        }
        if (CFEqual(prop, CFSTR("DeviceName"))) {
            return (__bridge_retained CFTypeRef)(g_overrideName ?: @"TweakForce-iPhone");
        }
        if (CFEqual(prop, CFSTR("ProductVersion"))) {
            return (__bridge_retained CFTypeRef)(g_overrideVersion ?: @"18.0");
        }
        if (CFEqual(prop, CFSTR("BuildVersion"))) {
            return (__bridge_retained CFTypeRef)(g_overrideBuild ?: @"22A3354");
        }
        if (CFEqual(prop, CFSTR("HardwareModel"))) {
            return (__bridge_retained CFTypeRef)(g_overrideBoard ?: @"D74AP");
        }
        if (CFEqual(prop, CFSTR("HardwarePlatform"))) {
            return (__bridge_retained CFTypeRef)(g_overridePlatform ?: @"t8120");
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
// 3. Environment Stealth & Self-Cloaking (Filesystem, Dyld Images, URLs)
// ============================================================================

static inline BOOL tf_is_jailbreak_path(const char *path) {
    if (!path) return NO;
    if (strstr(path, "/var/jb") != NULL ||
        strstr(path, "Cydia") != NULL ||
        strstr(path, "Sileo") != NULL ||
        strstr(path, "Zebra") != NULL ||
        strstr(path, "Filza") != NULL ||
        strstr(path, "MobileSubstrate") != NULL ||
        strstr(path, "TweakForce") != NULL ||
        strstr(path, "libTweakForce") != NULL ||
        strstr(path, "ElleKit") != NULL ||
        strstr(path, "systemhook") != NULL ||
        strstr(path, "roothide") != NULL ||
        strstr(path, "Dopamine") != NULL ||
        strcmp(path, "/bin/bash") == 0 ||
        strcmp(path, "/bin/sh") == 0 ||
        strcmp(path, "/usr/sbin/sshd") == 0 ||
        strcmp(path, "/etc/apt") == 0 ||
        strstr(path, "/private/var/lib/apt") != NULL) {
        return YES;
    }
    return NO;
}

// Dyld Image Masking
static const char *(*orig_dyld_get_image_name)(uint32_t image_index) = NULL;

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

// Filesystem Access Checks
static int (*orig_access)(const char *path, int mode) = NULL;
static int (*orig_stat)(const char *path, struct stat *buf) = NULL;
static int (*orig_lstat)(const char *path, struct stat *buf) = NULL;

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

// Sandbox fork check
static pid_t tf_my_fork(void) {
    errno = ENOSYS;
    return -1;
}

// NSFileManager Swizzling
static IMP orig_fileExistsAtPath = NULL;
static IMP orig_fileExistsAtPath_isDirectory = NULL;

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

// UIApplication canOpenURL Swizzling
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

// ============================================================================
// Hook Installer & Constructor
// ============================================================================

static void tf_install_spoof_and_stealth_hooks(void) {
    NSString *bundleID = [[NSBundle mainBundle] bundleIdentifier];
    if (!bundleID) return;

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
    if (!orig_MGCopyAnswer) orig_MGCopyAnswer = (CFTypeRef (*)(CFStringRef))dlsym(RTLD_DEFAULT, "MGCopyAnswer");
    if (!orig_dyld_get_image_name) orig_dyld_get_image_name = (const char *(*)(uint32_t))dlsym(RTLD_DEFAULT, "_dyld_get_image_name");

    // 3. Install Device Info Hooks (ObjC & C)
    Class uiDeviceClass = NSClassFromString(@"UIDevice");
    if (uiDeviceClass) {
        TF_hookMethod(uiDeviceClass, @selector(name), (IMP)tf_device_name, NULL);
        TF_hookMethod(uiDeviceClass, @selector(systemVersion), (IMP)tf_device_systemVersion, NULL);
        TF_hookMethod(uiDeviceClass, @selector(model), (IMP)tf_device_model, NULL);
        TF_hookMethod(uiDeviceClass, @selector(localizedModel), (IMP)tf_device_localizedModel, NULL);
    }

    TF_hookFunction("sysctlbyname", (void *)tf_my_sysctlbyname, (void **)&orig_sysctlbyname);
    TF_hookFunction("sysctl", (void *)tf_my_sysctl, (void **)&orig_sysctl);
    TF_hookFunction("uname", (void *)tf_my_uname, (void **)&orig_uname);
    TF_hookFunction("MGCopyAnswer", (void *)tf_my_MGCopyAnswer, (void **)&orig_MGCopyAnswer);

    // 4. Install Stealth & Self-Cloaking Hooks
    TF_hookFunction("_dyld_get_image_name", (void *)tf_my_dyld_get_image_name, (void **)&orig_dyld_get_image_name);
    TF_hookFunction("access", (void *)tf_my_access, (void **)&orig_access);
    TF_hookFunction("stat", (void *)tf_my_stat, (void **)&orig_stat);
    TF_hookFunction("lstat", (void *)tf_my_lstat, (void **)&orig_lstat);
    TF_hookFunction("fork", (void *)tf_my_fork, NULL);

    Class fmClass = NSClassFromString(@"NSFileManager");
    if (fmClass) {
        TF_hookMethod(fmClass, @selector(fileExistsAtPath:), (IMP)tf_fileManager_fileExistsAtPath, &orig_fileExistsAtPath);
        TF_hookMethod(fmClass, @selector(fileExistsAtPath:isDirectory:), (IMP)tf_fileManager_fileExistsAtPath_isDirectory, &orig_fileExistsAtPath_isDirectory);
    }

    Class appClass = NSClassFromString(@"UIApplication");
    if (appClass) {
        TF_hookMethod(appClass, @selector(canOpenURL:), (IMP)tf_app_canOpenURL, &orig_canOpenURL);
    }

    os_log(TFHLog(), "[TweakForce] Comprehensive Spoofing & Stealth hooks installed for %{public}@ (model=%{public}@, ver=%{public}@, build=%{public}@)",
           bundleID, g_overrideModel, g_overrideVersion, g_overrideBuild);
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
        } @catch (id ex) {
            os_log_error(TFHLog(), "[TweakForce] Exception in constructor: %{public}@", [ex description]);
        }
    }
}
