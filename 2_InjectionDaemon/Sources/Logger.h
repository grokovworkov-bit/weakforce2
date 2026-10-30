/*
 * ============================================================================
 *  TweakForce — Logger.h  (InjectionDaemon)
 * ============================================================================
 *  EN: Centralised logging: writes to os_log AND to a rolling log file so the
 *      Manager app / TestApp can display it. Thread-safe.
 *  RU: Централизованное логирование: пишет в os_log И в файл с ротацией,
 *      чтобы Manager app / TestApp могли его показать. Потокобезопасно.
 * ============================================================================
 */
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, TFLogLevel) {
    TFLogLevelDebug = 0,
    TFLogLevelInfo,
    TFLogLevelWarn,
    TFLogLevelError,
};

@interface Logger : NSObject

+ (instancetype)shared;

/// Configure destination file (created if needed). / Настроить файл-назначение.
- (void)setLogFilePath:(NSString *)path;

- (void)log:(TFLogLevel)level format:(NSString *)format, ... NS_FORMAT_FUNCTION(2,3);

/// Read back the last N bytes of the log file (for GET_LOG command).
/// Прочитать последние N байт лог-файла (для команды GET_LOG).
- (NSString *)tail:(NSUInteger)maxBytes;

@end

// Convenience macros / Удобные макросы
#define TFLogD(...) [[Logger shared] log:TFLogLevelDebug format:__VA_ARGS__]
#define TFLogI(...) [[Logger shared] log:TFLogLevelInfo  format:__VA_ARGS__]
#define TFLogW(...) [[Logger shared] log:TFLogLevelWarn  format:__VA_ARGS__]
#define TFLogE(...) [[Logger shared] log:TFLogLevelError format:__VA_ARGS__]

NS_ASSUME_NONNULL_END
