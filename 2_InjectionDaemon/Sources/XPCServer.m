/*
 * TweakForce — XPCServer.m (InjectionDaemon)
 * EN: CFMessagePort local server. Decodes a JSON request dictionary, runs the
 *     command and returns a JSON response. All errors logged.
 * RU: Локальный сервер CFMessagePort. Декодирует JSON-словарь запроса,
 *     выполняет команду и возвращает JSON-ответ. Все ошибки логируются.
 * VERIFY: from Manager app send PING -> expect {"ok":true,"pong":...}.
 */
#import "XPCServer.h"
#import "ConfigLoader.h"
#import "InjectionEngine.h"
#import "Logger.h"

// Message IDs / Идентификаторы сообщений
enum { TF_MSGID_REQUEST = 0x1 };

static CFDataRef TFHandleMessage(CFMessagePortRef port, SInt32 msgid, CFDataRef data, void *info);

@implementation XPCServer {
    CFMessagePortRef _port;
    CFRunLoopSourceRef _src;
}

+ (instancetype)shared {
    static XPCServer *s; static dispatch_once_t once;
    dispatch_once(&once, ^{ s = [[XPCServer alloc] init]; });
    return s;
}

- (BOOL)startWithPortName:(NSString *)portName {
    CFMessagePortContext ctx = {0, (__bridge void *)self, NULL, NULL, NULL};
    Boolean shouldFree = false;
    _port = CFMessagePortCreateLocal(kCFAllocatorDefault,
                                     (__bridge CFStringRef)portName,
                                     TFHandleMessage, &ctx, &shouldFree);
    if (!_port) {
        TFLogE(@"XPCServer: CFMessagePortCreateLocal failed for %@ (already running?)", portName);
        return NO;
    }
    _src = CFMessagePortCreateRunLoopSource(kCFAllocatorDefault, _port, 0);
    if (!_src) { TFLogE(@"XPCServer: run loop source failed"); return NO; }
    CFRunLoopAddSource(CFRunLoopGetMain(), _src, kCFRunLoopCommonModes);
    TFLogI(@"XPCServer: listening on %@", portName);
    return YES;
}

- (void)stop {
    if (_src) { CFRunLoopRemoveSource(CFRunLoopGetMain(), _src, kCFRunLoopCommonModes); CFRelease(_src); _src = NULL; }
    if (_port) { CFMessagePortInvalidate(_port); CFRelease(_port); _port = NULL; }
    TFLogI(@"XPCServer: stopped");
}

@end

// --- Command dispatch ------------------------------------------------------
static NSData *TFEncode(NSDictionary *dict) {
    NSError *e = nil;
    NSData *d = [NSJSONSerialization dataWithJSONObject:dict options:0 error:&e];
    if (!d) TFLogE(@"XPCServer: encode failed: %@", e);
    return d ?: [NSData data];
}

static CFDataRef TFHandleMessage(CFMessagePortRef port, SInt32 msgid, CFDataRef data, void *info) {
    @autoreleasepool {
        NSData *req = (__bridge NSData *)data;
        NSDictionary *msg = nil;
        if (req) {
            NSError *e = nil;
            id parsed = [NSJSONSerialization JSONObjectWithData:req options:0 error:&e];
            if ([parsed isKindOfClass:NSDictionary.class]) msg = parsed;
            else TFLogW(@"XPCServer: bad request json: %@", e);
        }
        NSString *cmd = msg[@"cmd"] ?: @"";
        NSDictionary *resp;

        if ([cmd isEqualToString:@"PING"]) {
            resp = @{ @"ok": @YES, @"pong": @([[NSDate date] timeIntervalSince1970]) };

        } else if ([cmd isEqualToString:@"GET_STATUS"]) {
            resp = @{ @"ok": @YES,
                      @"port": [ConfigLoader shared].daemonPortName,
                      @"pid": @(getpid()),
                      @"uptime": @([[NSProcessInfo processInfo] systemUptime]) };

        } else if ([cmd isEqualToString:@"SET_TWEAK_FOR_APP"]) {
            NSString *bundle = msg[@"bundle"]; BOOL on = [msg[@"enabled"] boolValue];
            BOOL ok = bundle.length ? [[ConfigLoader shared] setInjection:on forBundle:bundle] : NO;
            resp = @{ @"ok": @(ok) };

        } else if ([cmd isEqualToString:@"INJECT_NOW"]) {
            NSString *bundle = msg[@"bundle"]; pid_t pid = (pid_t)[msg[@"pid"] intValue];
            NSArray *dylibs = [[ConfigLoader shared] dylibsForBundle:bundle];
            TFInjectionResult r = (pid > 0)
                ? [[InjectionEngine shared] injectIntoPid:pid bundle:bundle dylibs:dylibs]
                : TFInjectionResultTaskForPidFailed;
            resp = @{ @"ok": @(r == TFInjectionResultSuccess),
                      @"result": [InjectionEngine describeResult:r] };

        } else if ([cmd isEqualToString:@"GET_LOG"]) {
            NSUInteger n = [msg[@"bytes"] unsignedIntegerValue] ?: 8192;
            resp = @{ @"ok": @YES, @"log": [[Logger shared] tail:n] };

        } else {
            resp = @{ @"ok": @NO, @"error": [NSString stringWithFormat:@"unknown cmd: %@", cmd] };
        }
        NSData *out = TFEncode(resp);
        return CFBridgingRetain(out);   // caller releases
    }
}
