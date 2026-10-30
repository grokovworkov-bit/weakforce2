/*
 * ============================================================================
 *  TweakForce — InjectionEngine.h (2_InjectionDaemon)
 * ============================================================================
 *  НАЗНАЧЕНИЕ:
 *  Движок инъекции dylib в целевые процессы.
 *
 *  МЕХАНИЗМЫ ИНЪЕКЦИИ:
 *  1. Механизм A (Pre-Launch):
 *     Регистрация DYLD_INSERT_LIBRARIES в файле предзагрузки окружения
 *     (/var/jb/etc/tweakforce_preload.env), который LoaderPatch в процессе
 *     bootstrap считывает перед fork+exec целевого приложения.
 *
 *  2. Механизм B (Post-Launch, arm64e PAC-aware):
 *     Выполняет инъекцию в уже работающий процесс через mach_vm_remap,
 *     dlopen trampoline и arm_thread_state64_set_pc_fptr (PAC bypass).
 * ============================================================================
 */

#import <Foundation/Foundation.h>
#import <mach/mach.h>
#import "PACBypass.h"

NS_ASSUME_NONNULL_BEGIN

/// Результат выполнения инъекции
typedef NS_ENUM(NSInteger, InjectionResult) {
    kInjectionSuccess = 0,   ///< Инъекция успешно выполнена
    kInjectionSkipped,       ///< Процесс пропущен (не в whitelist / нет библиотек)
    kInjectionFailed,        ///< Ошибка task_for_pid или выделения памяти
    kInjectionPACError       ///< Ошибка подписи PAC / thread_set_state на arm64e
};

// Псевдонимы типов для обратной совместимости
typedef InjectionResult TFInjectionResult;
#define TFInjectionResultSuccess           kInjectionSuccess
#define TFInjectionResultAlreadyInjected   kInjectionSkipped
#define TFInjectionResultTaskForPidFailed  kInjectionFailed
#define TFInjectionResultAllocFailed       kInjectionFailed
#define TFInjectionResultThreadFailed      kInjectionPACError
#define TFInjectionResultNoDylibs          kInjectionSkipped
#define TFInjectionResultNotPermitted      kInjectionPACError

@interface InjectionEngine : NSObject

/// Общий синглтон движка инъекции
+ (instancetype)shared;

/// Список разрешенных идентификаторов bundle (whitelist)
@property (nonatomic, copy) NSArray<NSString *> *whitelistBundleIDs;

/// Отображение bundleID -> путь к внедряемой библиотеке
@property (nonatomic, copy) NSDictionary<NSString *, NSString *> *injectionDylibPaths;

#pragma mark - Основные методы инъекции

/**
 * Механизм B: внедрение dylib в запущенный процесс по PID с PAC bypass.
 * Получает task_t через task_for_pid и вызывает pac_inject_into_task.
 */
- (InjectionResult)injectDylib:(NSString *)path intoPID:(pid_t)pid;

/**
 * Механизм B: внедрение dylib в задачу task_t с PAC bypass.
 * Напрямую вызывает pac_inject_into_task.
 */
- (InjectionResult)injectDylib:(NSString *)path intoTask:(task_t)task;

/**
 * Проверяет, разрешена ли инъекция для указанного bundleID.
 */
- (BOOL)isProcessInWhitelist:(NSString *)bundleID;

/**
 * Возвращает человекочитаемое описание результата инъекции.
 */
+ (NSString *)descriptionForResult:(InjectionResult)result;

#pragma mark - Механизм A (Pre-Launch)

/**
 * Механизм A: регистрирует окружение предзагрузки для bundle перед fork/exec.
 * Сохраняет записи в /var/jb/etc/tweakforce_preload.env для LoaderPatch.
 */
- (BOOL)registerPreLaunchInjectionForBundle:(NSString *)bundleID
                                     dylibs:(NSArray<NSString *> *)dylibs;

#pragma mark - Методы обратной совместимости

- (InjectionResult)injectIntoPid:(pid_t)pid
                          bundle:(NSString *)bundleID
                          dylibs:(NSArray<NSString *> *)dylibs;

+ (NSString *)describeResult:(InjectionResult)r;

@end

NS_ASSUME_NONNULL_END
