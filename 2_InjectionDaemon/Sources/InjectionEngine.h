/*
 * ============================================================================
 *  TweakForce — InjectionEngine.h  (InjectionDaemon)
 * ============================================================================
 *  EN: Two injection mechanisms:
 *      A) Pre-launch environment injection — register DYLD_INSERT_LIBRARIES
 *         for the target via launchd/environment so the dylib is present at
 *         process start (cleanest, mirrors Bootstrap itself).
 *      B) Post-launch mach_inject — task_for_pid + vm_allocate/vm_write +
 *         thread_create_running to dlopen() the dylib in a running process
 *         (fallback). See README for PAC/arm64e honesty note.
 *  RU: Два механизма инъекции:
 *      A) Pre-launch environment injection — регистрируем
 *         DYLD_INSERT_LIBRARIES для цели через launchd/окружение, чтобы dylib
 *         присутствовал на старте процесса (самый чистый способ).
 *      B) Post-launch mach_inject — task_for_pid + vm_allocate/vm_write +
 *         thread_create_running для dlopen() в уже запущенном процессе
 *         (fallback). См. README про PAC/arm64e.
 * ============================================================================
 */
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, TFInjectionResult) {
    TFInjectionResultSuccess = 0,
    TFInjectionResultAlreadyInjected,
    TFInjectionResultTaskForPidFailed,
    TFInjectionResultAllocFailed,
    TFInjectionResultThreadFailed,
    TFInjectionResultNoDylibs,
    TFInjectionResultNotPermitted,
};

@interface InjectionEngine : NSObject

+ (instancetype)shared;

/// Mechanism A: register pre-launch DYLD env for a bundle's dylibs.
/// Механизм A: зарегистрировать pre-launch DYLD env для dylib bundle.
- (BOOL)registerPreLaunchInjectionForBundle:(NSString *)bundleID
                                     dylibs:(NSArray<NSString *> *)dylibs;

/// Mechanism B: inject dylibs into a running pid via mach.
/// Механизм B: внедрить dylib в запущенный pid через mach.
- (TFInjectionResult)injectIntoPid:(pid_t)pid
                            bundle:(NSString *)bundleID
                            dylibs:(NSArray<NSString *> *)dylibs;

/// Convenience: choose best mechanism for a freshly launched process.
/// Удобство: выбрать лучший механизм для только что запущенного процесса.
- (TFInjectionResult)handleLaunchedPid:(pid_t)pid bundle:(NSString *)bundleID;

/// Human-readable result string. / Человекочитаемая строка результата.
+ (NSString *)describeResult:(TFInjectionResult)r;

@end

NS_ASSUME_NONNULL_END
