/* TweakForce — DiagnosticReporter.h
 * EN: Collects & publishes injection state: loaded dylibs, hook status,
 *     daemon reachability, DYLD env. Writes file + os_log + Darwin notify.
 * RU: Собирает и публикует состояние инъекции: загруженные dylib, статус
 *     хуков, доступность daemon, DYLD env. Файл + os_log + Darwin notify. */
#import <Foundation/Foundation.h>
NS_ASSUME_NONNULL_BEGIN
@interface DiagnosticReporter : NSObject
+ (instancetype)shared;
/// Build a diagnostics dictionary. / Собрать словарь диагностики.
- (NSDictionary *)snapshot;
/// Write snapshot to file + os_log + post Darwin notification.
/// Записать снимок в файл + os_log + послать Darwin-уведомление.
- (void)publish;
@end
NS_ASSUME_NONNULL_END
