/* TweakForce — DiagnosticReporter.m
 * VERIFY: read /var/jb/var/mobile/Library/TweakForce/diag/<proc>.json. */
#import "DiagnosticReporter.h"
#import "HookRegistry.h"
#import <mach-o/dyld.h>
#import <os/log.h>
#import <notify.h>

#define TF_DARWIN_NOTE "com.tweakforce.diagnostics.updated"

@implementation DiagnosticReporter

+ (instancetype)shared {
    static DiagnosticReporter *s; static dispatch_once_t once;
    dispatch_once(&once, ^{ s = [DiagnosticReporter new]; });
    return s;
}

- (NSArray<NSString *> *)loadedImages {
    uint32_t n = _dyld_image_count();
    NSMutableArray *a = [NSMutableArray arrayWithCapacity:n];
    for (uint32_t i = 0; i < n; i++) {
        const char *name = _dyld_get_image_name(i);
        if (name) {
            NSString *s = [NSString stringWithUTF8String:name];
            if (s) [a addObject:s];
        }
    }
    return a;
}

- (NSDictionary *)snapshot {
    NSProcessInfo *pi = NSProcessInfo.processInfo;
    NSArray *images = [self loadedImages];
    BOOL frameworkLoaded = NO;
    for (NSString *img in images) { if ([img containsString:@"TweakForceHooks"]) { frameworkLoaded = YES; break; } }
    NSString *dyldEnv = pi.environment[@"DYLD_INSERT_LIBRARIES"] ?: @"";
    return @{
        @"process": pi.processName ?: @"?",
        @"pid": @(getpid()),
        @"frameworkLoaded": @(frameworkLoaded),
        @"imageCount": @(images.count),
        @"images": images,
        @"hooks": [[HookRegistry shared] allHooks] ?: @[],
        @"DYLD_INSERT_LIBRARIES": dyldEnv,
        @"timestamp": @([[NSDate date] timeIntervalSince1970]),
    };
}

- (void)publish {
    @try {
        NSDictionary *snap = [self snapshot];
        // os_log
        os_log(os_log_create("com.tweakforce","Diagnostics"),
               "[TweakForce] diag: fw=%{public}@ images=%{public}@ hooks=%{public}@",
               snap[@"frameworkLoaded"], snap[@"imageCount"], @([snap[@"hooks"] count]));
        // File
        NSString *dir = @"/var/jb/var/mobile/Library/TweakForce/diag";
        NSError *err = nil;
        if ([NSFileManager.defaultManager createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:&err]) {
            NSString *file = [dir stringByAppendingPathComponent:
                              [NSString stringWithFormat:@"%@.json", snap[@"process"]]];
            if ([NSJSONSerialization isValidJSONObject:snap]) {
                NSData *d = [NSJSONSerialization dataWithJSONObject:snap options:NSJSONWritingPrettyPrinted error:&err];
                if (d) [d writeToFile:file atomically:YES];
            }
        }
        // Darwin notify
        notify_post(TF_DARWIN_NOTE);
    } @catch (id ex) {
        // Sandboxed apps or dyld exceptions must never crash host process
    }
}

@end
