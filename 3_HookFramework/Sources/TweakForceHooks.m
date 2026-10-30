/*
 * TweakForce — TweakForceHooks.m — implementation.
 * EN: MSHookFunction (ElleKit) + fishhook with vm_protect fallback; safe
 *     method_setImplementation swizzling for ObjC; CFMessagePort client.
 * RU: MSHookFunction (ElleKit) + fallback на fishhook с vm_protect; безопасный
 *     swizzling через method_setImplementation; клиент CFMessagePort.
 * VERIFY: call TF_isInjectionActive() in a host app; see DiagnosticReporter.
 */
#import "TweakForceHooks.h"
#import "fishhook.h"
#import "HookRegistry.h"
#import "DiagnosticReporter.h"
#import <os/log.h>
#import <dlfcn.h>
#import <UIKit/UIKit.h>
#import <sys/utsname.h>
#import <sys/sysctl.h>

#define TF_PORT_NAME CFSTR("com.tweakforce.daemon")
static os_log_t TFHLog(void){ static os_log_t l; static dispatch_once_t o;
    dispatch_once(&o, ^{ l = os_log_create("com.tweakforce","Hooks"); }); return l; }

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

static NSString *g_overrideName = nil;
static NSString *g_overrideModel = nil;
static NSString *g_overrideVersion = nil;

static int (*orig_sysctlbyname)(const char *, void *, size_t *, void *, size_t) = NULL;
static int (*orig_uname)(struct utsname *) = NULL;

static int tf_my_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (name && !newp) {
        if ((strcmp(name, "hw.machine") == 0 || strcmp(name, "hw.model") == 0) && g_overrideModel.length > 0) {
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
    if (ret == 0 && buf && g_overrideModel.length > 0) {
        strncpy(buf->machine, g_overrideModel.UTF8String, sizeof(buf->machine) - 1);
        buf->machine[sizeof(buf->machine) - 1] = '\0';
    }
    return ret;
}

static NSString *tf_device_name(id self, SEL _cmd) {
    return g_overrideName ?: @"iPhone";
}

static NSString *tf_device_systemVersion(id self, SEL _cmd) {
    return g_overrideVersion ?: @"18.0";
}

static void tf_install_spoof_hooks(void) {
    NSString *bundleID = [[NSBundle mainBundle] bundleIdentifier];
    if (!bundleID) return;

    // Pre-initialize real function pointers so they are NEVER NULL
    if (!orig_sysctlbyname) {
        orig_sysctlbyname = (int (*)(const char *, void *, size_t *, void *, size_t))dlsym(RTLD_DEFAULT, "sysctlbyname");
    }
    if (!orig_uname) {
        orig_uname = (int (*)(struct utsname *))dlsym(RTLD_DEFAULT, "uname");
    }

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

    if (!values || values.count == 0) {
        g_overrideModel = @"iPhone15,3";
        g_overrideName = @"TweakForce-iPhone";
        g_overrideVersion = @"18.0";
    } else {
        g_overrideName = values[@"device_name_override"] ?: @"TweakForce-iPhone";
        g_overrideModel = values[@"device_model_override"] ?: @"iPhone15,3";
        g_overrideVersion = values[@"system_version_override"] ?: @"18.0";
    }

    Class uiDeviceClass = NSClassFromString(@"UIDevice");
    if (uiDeviceClass) {
        TF_hookMethod(uiDeviceClass, @selector(name), (IMP)tf_device_name, NULL);
        TF_hookMethod(uiDeviceClass, @selector(systemVersion), (IMP)tf_device_systemVersion, NULL);
    }

    TF_hookFunction("sysctlbyname", (void *)tf_my_sysctlbyname, (void **)&orig_sysctlbyname);
    TF_hookFunction("uname", (void *)tf_my_uname, (void **)&orig_uname);

    os_log(TFHLog(), "[TweakForce] spoof hooks installed for %{public}@ (model=%{public}@, ver=%{public}@)",
           bundleID, g_overrideModel, g_overrideVersion);
}

// Constructor: publish diagnostics and install spoof hooks when loaded into any process.
__attribute__((constructor))
static void TweakForceHooksInit(void) {
    @autoreleasepool {
        @try {
            os_log(TFHLog(), "[TweakForce] libTweakForceHooks loaded into %{public}s",
                   [[NSProcessInfo processInfo] processName].UTF8String ?: "?");
            tf_install_spoof_hooks();
            [[DiagnosticReporter shared] publish];
        } @catch (id ex) {
            os_log_error(TFHLog(), "[TweakForce] Exception in constructor: %{public}@", [ex description]);
        }
    }
}
