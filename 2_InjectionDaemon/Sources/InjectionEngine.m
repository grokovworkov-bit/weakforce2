/*
 * ============================================================================
 *  TweakForce — InjectionEngine.m (2_InjectionDaemon)
 * ============================================================================
 *  НАЗНАЧЕНИЕ:
 *  Реализация конвейера инъекции (Pipeline) для Механизма A и Механизма B.
 *
 *  МЕХАНИЗМ А (Pre-Launch Injection):
 *  ==========================================================================
 *  Теоретическая стратегия 1: xpc_connection_create("com.apple.launchd", ...).
 *  Почему это НЕ работает: в современных iOS (начиная с iOS 15+) прямой доступ к
 *  приватным рутинам модификации окружения спавна launchd защищен MACF-политиками
 *  и требует закрытых прав entitlments ядра. Вызов xpc_connection_create к launchd
 *  отклоняется или игнорирует кастомные переменные окружения для сторонних процессов.
 *
 *  Рабочая стратегия 2 для Jailbreak (RootHide / Dopamine):
 *  Запись конфигурации переменных в глобальный файл предзагрузки:
 *  /var/jb/etc/tweakforce_preload.env и /var/jb/var/mobile/Library/TweakForce/prelaunch/<bundle>.env.
 *  Патч LoaderPatch, работающий внутри процесса bootstrap, перехватывает вызовы
 *  принятия решений о спавне и форсирует экспорт DYLD_INSERT_LIBRARIES в целевой
 *  процесс в момент его рождения.
 *
 *  МЕХАНИЗМ B (Post-Launch Injection на arm64e):
 *  ==========================================================================
 *  Работает через модуль PACBypass.c:
 *  1. Получение порта задачи через task_for_pid (требует get-task-allow/task_for_pid-allow).
 *  2. mach_vm_remap уже подписанной кодовой страницы tf_bootstrap_trampoline.
 *  3. Подписание PC нового потока через arm_thread_state64_set_pc_fptr.
 *  4. Вызов dlopen через dyld shared cache в контексте нового потока.
 * ============================================================================
 */

#import "InjectionEngine.h"
#import "ConfigLoader.h"
#import "Logger.h"
#import <mach/mach.h>
#import <os/lock.h>

@implementation InjectionEngine {
    os_unfair_lock _lock;
}

+ (instancetype)shared {
    static InjectionEngine *s;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        s = [[InjectionEngine alloc] init];
    });
    return s;
}

- (instancetype)init {
    if ((self = [super init])) {
        _lock = OS_UNFAIR_LOCK_INIT;
        _whitelistBundleIDs = @[];
        _injectionDylibPaths = @{};
        [self reloadConfiguration];
    }
    return self;
}

- (void)reloadConfiguration {
    os_unfair_lock_lock(&_lock);
    ConfigLoader *cfg = [ConfigLoader shared];
    // Заполняем whitelist и пути на основе конфига tweakforce.json
    NSMutableArray *wl = [NSMutableArray array];
    NSMutableDictionary *paths = [NSMutableDictionary dictionary];

    // Добавляем тестовые приложения и AIDA64, если они разрешены
    NSArray *candidates = @[@"com.tweakforce.testapp", @"com.finalwire.aida64"];
    for (NSString *bid in candidates) {
        if ([cfg shouldInjectBundle:bid]) {
            [wl addObject:bid];
            NSArray *dylibs = [cfg dylibsForBundle:bid];
            if (dylibs.firstObject) {
                paths[bid] = dylibs.firstObject;
            }
        }
    }

    _whitelistBundleIDs = [wl copy];
    _injectionDylibPaths = [paths copy];
    os_unfair_lock_unlock(&_lock);
}

#pragma mark - Проверка Whitelist

- (BOOL)isProcessInWhitelist:(NSString *)bundleID {
    if (bundleID.length == 0) {
        return NO;
    }

    // Проверяем локальный кэш
    os_unfair_lock_lock(&_lock);
    BOOL inLocal = [_whitelistBundleIDs containsObject:bundleID];
    os_unfair_lock_unlock(&_lock);

    if (inLocal) {
        return YES;
    }

    // Проверяем напрямую через ConfigLoader
    return [[ConfigLoader shared] shouldInjectBundle:bundleID];
}

#pragma mark - Описание результатов

+ (NSString *)descriptionForResult:(InjectionResult)result {
    switch (result) {
        case kInjectionSuccess:
            return @"Успех (kInjectionSuccess): библиотека успешно внедрена";
        case kInjectionSkipped:
            return @"Пропущено (kInjectionSkipped): приложение отсутствует в whitelist или нет библиотек";
        case kInjectionFailed:
            return @"Ошибка (kInjectionFailed): сбой task_for_pid или mach_vm_allocate/write";
        case kInjectionPACError:
            return @"PAC Ошибка (kInjectionPACError): отказ ядра при thread_set_state на arm64e";
    }
    return @"Неизвестный результат";
}

+ (NSString *)describeResult:(InjectionResult)r {
    return [self descriptionForResult:r];
}

#pragma mark - Механизм B: Post-Launch arm64e PAC Injection

- (InjectionResult)injectDylib:(NSString *)path intoPID:(pid_t)pid {
    if (pid <= 0) {
        TFLogE(@"[InjectionEngine] Некорректный PID: %d", pid);
        return kInjectionFailed;
    }
    if (path.length == 0) {
        TFLogE(@"[InjectionEngine] Пустой путь к dylib для PID %d", pid);
        return kInjectionSkipped;
    }

    TFLogI(@"[InjectionEngine] [Механизм B] Запуск инъекции '%@' в PID %d", path, pid);

    // Шаг 1: Получение task порта через task_for_pid
    // Требует entitlement get-task-allow и task_for_pid-allow
    task_t task = MACH_PORT_NULL;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
    if (kr != KERN_SUCCESS || task == MACH_PORT_NULL) {
        TFLogE(@"[InjectionEngine] task_for_pid(%d) failed: %s (kr=%d) — проверьте entitlements",
               pid, mach_error_string(kr), kr);
        return kInjectionFailed;
    }

    // Шаг 2: Вызов pac_inject_into_task из PACBypass.c
    InjectionResult result = [self injectDylib:path intoTask:task];

    // Шаг 3: Обязательное освобождение task порта
    mach_port_deallocate(mach_task_self(), task);

    TFLogI(@"[InjectionEngine] PID %d результат: %@", pid, [InjectionEngine descriptionForResult:result]);
    return result;
}

- (InjectionResult)injectDylib:(NSString *)path intoTask:(task_t)task {
    if (task == MACH_PORT_NULL) {
        TFLogE(@"[InjectionEngine] Недействительный task порт (MACH_PORT_NULL)");
        return kInjectionFailed;
    }
    if (path.length == 0) {
        TFLogE(@"[InjectionEngine] Пустой путь к библиотеке");
        return kInjectionSkipped;
    }

    // Вызываем PAC bypass модуль
    kern_return_t kr = pac_inject_into_task(task, path.fileSystemRepresentation);

    if (kr == KERN_SUCCESS) {
        return kInjectionSuccess;
    } else if (kr == KERN_PROTECTION_FAILURE || kr == KERN_INVALID_ARGUMENT) {
        TFLogE(@"[InjectionEngine] PAC отказ при thread_set_state: %s (kr=%d)",
               mach_error_string(kr), kr);
        return kInjectionPACError;
    } else {
        TFLogE(@"[InjectionEngine] Сбой mach вызова: %s (kr=%d)", mach_error_string(kr), kr);
        return kInjectionFailed;
    }
}

#pragma mark - Механизм A: Pre-Launch Injection

- (BOOL)registerPreLaunchInjectionForBundle:(NSString *)bundleID
                                     dylibs:(NSArray<NSString *> *)dylibs {
    if (dylibs.count == 0) {
        TFLogW(@"[InjectionEngine] [Механизм A] Нет dylib для %@", bundleID);
        return NO;
    }

    NSString *joined = [dylibs componentsJoinedByString:@":"];
    TFLogI(@"[InjectionEngine] [Механизм A] Регистрация предзагрузки для %@: %@", bundleID, joined);

    // 1. Сохраняем в глобальный каталог предзагрузки TweakForce
    NSString *dir = @"/var/jb/var/mobile/Library/TweakForce/prelaunch";
    NSError *err = nil;
    if (![NSFileManager.defaultManager createDirectoryAtPath:dir
                                 withIntermediateDirectories:YES
                                                  attributes:nil
                                                       error:&err]) {
        TFLogE(@"[InjectionEngine] Не удалось создать каталог %@: %@", dir, err);
    } else {
        NSString *bundleEnvFile = [dir stringByAppendingPathComponent:
                                   [NSString stringWithFormat:@"%@.env", bundleID]];
        NSDictionary *envDict = @{
            @"DYLD_INSERT_LIBRARIES": joined,
            @"bundleID": bundleID,
            @"timestamp": @([[NSDate date] timeIntervalSince1970])
        };
        [envDict writeToFile:bundleEnvFile atomically:YES];
    }

    // 2. Записываем в общий preload-файл джейлбрейка /var/jb/etc/tweakforce_preload.env
    NSString *globalEnvPath = @"/var/jb/etc/tweakforce_preload.env";
    NSString *line = [NSString stringWithFormat:@"%@=%@\n", bundleID, joined];
    NSData *lineData = [line dataUsingEncoding:NSUTF8StringEncoding];

    if (![NSFileManager.defaultManager fileExistsAtPath:globalEnvPath]) {
        [lineData writeToFile:globalEnvPath atomically:YES];
    } else {
        NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:globalEnvPath];
        if (fh) {
            [fh seekToEndOfFile];
            [fh writeData:lineData];
            [fh closeFile];
        }
    }

    TFLogI(@"[InjectionEngine] [Механизм A] Предзагрузка успешно зарегистрирована в %@", globalEnvPath);
    return YES;
}

#pragma mark - Совместимость с main.m и XPCServer.m

- (InjectionResult)injectIntoPid:(pid_t)pid
                          bundle:(NSString *)bundleID
                          dylibs:(NSArray<NSString *> *)dylibs {
    if (bundleID.length > 0 && ![self isProcessInWhitelist:bundleID]) {
        TFLogI(@"[InjectionEngine] Процесс %@ (pid %d) не входит в whitelist; инъекция пропущена",
               bundleID, pid);
        return kInjectionSkipped;
    }

    if (dylibs.count == 0) {
        TFLogW(@"[InjectionEngine] Нет dylib для инъекции в pid %d (%@)", pid, bundleID);
        return kInjectionSkipped;
    }

    InjectionResult overall = kInjectionSuccess;
    for (NSString *dylib in dylibs) {
        InjectionResult r = [self injectDylib:dylib intoPID:pid];
        if (r != kInjectionSuccess) {
            overall = r;
        }
    }
    return overall;
}

@end
