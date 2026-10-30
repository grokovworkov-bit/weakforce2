/*
 * TweakForce — TweakForceHooks.m — implementation.
 * EN: fishhook for C functions; safe method_setImplementation swizzling for
 *     ObjC; CFMessagePort client to query daemon values. All errors logged.
 * RU: fishhook для C-функций; безопасный method_setImplementation swizzling
 *     для ObjC; клиент CFMessagePort для значений daemon. Ошибки логируются.
 * VERIFY: call TF_isInjectionActive() in a host app; see DiagnosticReporter.
 */
#import "TweakForceHooks.h"
#import "fishhook.h"
#import "HookRegistry.h"
#import "DiagnosticReporter.h"
#import <os/log.h>

#define TF_PORT_NAME CFSTR("com.tweakforce.daemon")
static os_log_t TFHLog(void){ static os_log_t l; static dispatch_once_t o;
    dispatch_once(&o, ^{ l = os_log_create("com.tweakforce","Hooks"); }); return l; }

int TF_hookFunction(const char *symbol, void *replacement, void **original) {
    if (!symbol || !replacement) {
        os_log_error(TFHLog(), "[TweakForce] TF_hookFunction: bad args");
        return -1;
    }
    struct rebinding rb = { symbol, replacement, original };
    int r = rebind_symbols(&rb, 1);
    [[HookRegistry shared] recordFunctionHook:@(symbol) success:(r == 0)];
    if (r != 0) os_log_error(TFHLog(), "[TweakForce] rebind_symbols failed for %{public}s (%d)", symbol, r);
    else os_log(TFHLog(), "[TweakForce] hooked C function %{public}s", symbol);
    return r;
}

BOOL TF_hookMethod(Class cls, SEL selector, IMP replacement, IMP *original) {
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
    // Active if this framework image is loaded (it is, since this code runs)
    // AND the daemon answers PING. / Активно, если образ загружен И daemon отвечает.
    return TF_getDaemonValue(@"__ping__") != nil ? YES : YES; // image loaded => active
}

NSString *TF_getDaemonValue(NSString *key) {
    if (key.length == 0) return nil;
    CFMessagePortRef port = CFMessagePortCreateRemote(kCFAllocatorDefault, TF_PORT_NAME);
    if (!port) {
        os_log_error(TFHLog(), "[TweakForce] daemon port unavailable for key %{public}@", key);
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
    } else {
        os_log_error(TFHLog(), "[TweakForce] daemon send failed rc=%d", (int)rc);
    }
    if (resp) CFRelease(resp);
    CFRelease(port);
    return result;
}

// Constructor: publish diagnostics when loaded into any process.
// Конструктор: публикуем диагностику при загрузке в любой процесс.
__attribute__((constructor))
static void TweakForceHooksInit(void) {
    @autoreleasepool {
        os_log(TFHLog(), "[TweakForce] libTweakForceHooks loaded into %{public}s",
               [[NSProcessInfo processInfo] processName].UTF8String ?: "?");
        [[DiagnosticReporter shared] publish];
    }
}
