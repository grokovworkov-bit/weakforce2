/* TweakForce — HookRegistry.m — thread-safe via os_unfair_lock.
 * VERIFY: after hooks installed, -allHooks lists them with success flags. */
#import "HookRegistry.h"
#import <os/lock.h>
@implementation HookRegistry {
    os_unfair_lock _lock;
    NSMutableArray<NSDictionary *> *_hooks;
}
+ (instancetype)shared {
    static HookRegistry *s; static dispatch_once_t once;
    dispatch_once(&once, ^{ s = [HookRegistry new]; });
    return s;
}
- (instancetype)init { if ((self=[super init])){ _lock=OS_UNFAIR_LOCK_INIT; _hooks=[NSMutableArray array]; } return self; }
- (void)_add:(NSDictionary *)d { os_unfair_lock_lock(&_lock); [_hooks addObject:d]; os_unfair_lock_unlock(&_lock); }
- (void)recordFunctionHook:(NSString *)symbol success:(BOOL)ok {
    [self _add:@{ @"name": symbol ?: @"?", @"type": @"function", @"success": @(ok) }];
}
- (void)recordMethodHook:(NSString *)clsSel success:(BOOL)ok {
    [self _add:@{ @"name": clsSel ?: @"?", @"type": @"method", @"success": @(ok) }];
}
- (NSArray<NSDictionary *> *)allHooks {
    os_unfair_lock_lock(&_lock); NSArray *c = [_hooks copy]; os_unfair_lock_unlock(&_lock); return c;
}
@end
