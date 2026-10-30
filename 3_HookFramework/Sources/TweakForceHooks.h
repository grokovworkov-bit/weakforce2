/*
 * TweakForce — TweakForceHooks.h (public framework API / публичный API)
 * EN: Embeddable universal hook framework. Hook C functions (fishhook) and
 *     ObjC methods (safe swizzling), query injection state, fetch daemon values.
 * RU: Встраиваемый universal hook framework. Хуки C-функций (fishhook) и
 *     ObjC-методов (безопасный swizzling), проверка инъекции, значения daemon.
 * BUILD: part of 3_HookFramework (libTweakForceHooks.dylib + module map).
 */
#import <Foundation/Foundation.h>
#import <objc/runtime.h>

NS_ASSUME_NONNULL_BEGIN

#ifdef __cplusplus
extern "C" {
#endif

/// Hook a C function by symbol name. Returns 0 on success.
/// Хук C-функции по имени символа. 0 при успехе.
int TF_hookFunction(const char *symbol, void *replacement, void **original);

/// Hook an ObjC method. Returns YES on success, stores original IMP.
/// Хук ObjC-метода. YES при успехе, сохраняет оригинальный IMP.
BOOL TF_hookMethod(Class cls, SEL selector, IMP replacement, IMP _Nullable *original);

/// Is TweakForce injection active in this process?
/// Активна ли инъекция TweakForce в этом процессе?
BOOL TF_isInjectionActive(void);

/// Fetch a named value from the daemon (via CFMessagePort). May be nil.
/// Получить именованное значение от daemon (через CFMessagePort). Может быть nil.
NSString *_Nullable TF_getDaemonValue(NSString *key);

#ifdef __cplusplus
}
#endif

NS_ASSUME_NONNULL_END
