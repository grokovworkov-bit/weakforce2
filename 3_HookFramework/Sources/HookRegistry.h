/* TweakForce — HookRegistry.h
 * EN: Thread-safe registry of active hooks for diagnostics.
 * RU: Потокобезопасный реестр активных хуков для диагностики. */
#import <Foundation/Foundation.h>
NS_ASSUME_NONNULL_BEGIN
@interface HookRegistry : NSObject
+ (instancetype)shared;
- (void)recordFunctionHook:(NSString *)symbol success:(BOOL)ok;
- (void)recordMethodHook:(NSString *)clsSel success:(BOOL)ok;
/// Snapshot of all hooks: array of {name, type, success}. / Снимок всех хуков.
- (NSArray<NSDictionary *> *)allHooks;
@end
NS_ASSUME_NONNULL_END
