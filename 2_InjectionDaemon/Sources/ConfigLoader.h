/*
 * ============================================================================
 *  TweakForce — ConfigLoader.h  (InjectionDaemon)
 * ============================================================================
 *  EN: Loads and parses config/tweakforce.json. Exposes per-app injection
 *      settings, dylib lists and key/value overrides. Hot-reloadable.
 *  RU: Загружает и разбирает config/tweakforce.json. Предоставляет настройки
 *      инъекции по приложениям, списки dylib и key/value переопределения.
 *      Поддерживает горячую перезагрузку.
 * ============================================================================
 */
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface AppConfig : NSObject
@property (nonatomic, copy)   NSString *bundleID;
@property (nonatomic, assign) BOOL injection;
@property (nonatomic, assign) BOOL hiding;
@property (nonatomic, copy)   NSArray<NSString *> *dylibs;
@property (nonatomic, copy)   NSDictionary<NSString *, NSString *> *values;
@end

@interface ConfigLoader : NSObject

+ (instancetype)shared;

/// Path to the json config. Default resolved automatically.
/// Путь к json-конфигу. По умолчанию разрешается автоматически.
@property (nonatomic, copy) NSString *configPath;

/// (Re)load from disk. Returns NO + logs on failure.
/// (Пере)загрузить с диска. Возвращает NO + лог при ошибке.
- (BOOL)reload;

/// Config for a bundle, or nil. / Конфиг для bundle, или nil.
- (nullable AppConfig *)configForBundle:(NSString *)bundleID;

/// Should this bundle be injected? / Нужно ли внедрять в этот bundle?
- (BOOL)shouldInjectBundle:(NSString *)bundleID;

/// Dylibs to inject for a bundle (incl. global dylibs).
/// Dylib для инъекции в bundle (включая глобальные).
- (NSArray<NSString *> *)dylibsForBundle:(NSString *)bundleID;

/// Named value override for a bundle. / Именованное переопределение для bundle.
- (nullable NSString *)valueForKey:(NSString *)key bundle:(NSString *)bundleID;

/// Daemon settings / Настройки daemon
- (NSString *)daemonPortName;
- (NSString *)daemonLogPath;
- (NSTimeInterval)pollInterval;

/// Persist an injection toggle for a bundle (used by SET_TWEAK_FOR_APP).
/// Сохранить тумблер инъекции для bundle (используется SET_TWEAK_FOR_APP).
- (BOOL)setInjection:(BOOL)enabled forBundle:(NSString *)bundleID;

@end

NS_ASSUME_NONNULL_END
