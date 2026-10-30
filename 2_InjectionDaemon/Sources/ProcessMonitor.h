/*
 * ============================================================================
 *  TweakForce — ProcessMonitor.h  (InjectionDaemon)
 * ============================================================================
 *  EN: Detects newly launched processes. Primary mechanism: kqueue +
 *      EVFILT_PROC (requires knowing pids; we combine with a lightweight
 *      proc_listpids poll to discover new pids). Fallback: pure polling.
 *      For each new process it resolves (pid, bundleID, executable path)
 *      and notifies via a callback block.
 *  RU: Обнаруживает только что запущенные процессы. Основной механизм:
 *      kqueue + EVFILT_PROC (нужны pids; комбинируем с лёгким опросом
 *      proc_listpids для поиска новых pid). Fallback: чистый polling.
 *      Для каждого нового процесса определяет (pid, bundleID, путь) и
 *      уведомляет через callback-блок.
 * ============================================================================
 */
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef struct {
    pid_t pid;
} TFProcEventRaw;

/// Called on a background queue for every newly observed process.
/// Вызывается на фоновой очереди для каждого нового процесса.
typedef void (^TFProcessLaunchHandler)(pid_t pid,
                                       NSString *_Nullable bundleID,
                                       NSString *_Nullable executablePath);

@interface ProcessMonitor : NSObject

- (instancetype)initWithPollInterval:(NSTimeInterval)interval;

/// Begin monitoring. Handler invoked for each new process.
/// Начать мониторинг. Handler вызывается для каждого нового процесса.
- (void)startWithHandler:(TFProcessLaunchHandler)handler;

/// Stop monitoring and release resources. / Остановить и освободить ресурсы.
- (void)stop;

@end

NS_ASSUME_NONNULL_END
