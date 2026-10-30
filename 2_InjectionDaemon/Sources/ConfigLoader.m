/*
 * ============================================================================
 *  TweakForce — ConfigLoader.m  (InjectionDaemon)
 * ============================================================================
 *  EN: Implementation. Thread-safe cached parse (os_unfair_lock).
 *  RU: Реализация. Потокобезопасный кэшированный разбор (os_unfair_lock).
 *
 *  VERIFY: set injection:true for a bundle, call -shouldInjectBundle: → YES.
 * ============================================================================
 */
#import "ConfigLoader.h"
#import "Logger.h"
#import <os/lock.h>

// Default config search paths / Пути поиска конфига по умолчанию
static NSString *const kConfigCandidates[] = {
    @"/var/jb/etc/tweakforce.json",
    @"/var/jb/var/mobile/Library/TweakForce/tweakforce.json",
};

@implementation AppConfig
@end

@implementation ConfigLoader {
    os_unfair_lock _lock;
    NSMutableDictionary<NSString *, AppConfig *> *_apps;
    NSArray<NSString *> *_globalDylibs;
    NSString *_portName;
    NSString *_logPath;
    NSTimeInterval _poll;
}

+ (instancetype)shared {
    static ConfigLoader *s; static dispatch_once_t once;
    dispatch_once(&once, ^{ s = [[ConfigLoader alloc] init]; });
    return s;
}

- (instancetype)init {
    if ((self = [super init])) {
        _lock = OS_UNFAIR_LOCK_INIT;
        _apps = [NSMutableDictionary dictionary];
        _globalDylibs = @[];
        _portName = @"com.tweakforce.daemon";
        _logPath  = @"/var/jb/var/mobile/Library/Logs/TweakForce/daemon.log";
        _poll = 1.0;
        [self reload];
    }
    return self;
}

- (NSString *)resolveConfigPath {
    if (self.configPath.length) return self.configPath;
    for (size_t i = 0; i < sizeof(kConfigCandidates)/sizeof(kConfigCandidates[0]); i++) {
        if ([NSFileManager.defaultManager fileExistsAtPath:kConfigCandidates[i]]) {
            return kConfigCandidates[i];
        }
    }
    return kConfigCandidates[0];
}

- (BOOL)reload {
    NSString *path = [self resolveConfigPath];
    NSData *data = [NSData dataWithContentsOfFile:path];
    if (!data) {
        TFLogE(@"ConfigLoader: cannot read %@", path);
        return NO;
    }
    NSError *err = nil;
    NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:&err];
    if (![json isKindOfClass:NSDictionary.class]) {
        TFLogE(@"ConfigLoader: bad JSON in %@: %@", path, err);
        return NO;
    }

    NSMutableDictionary *apps = [NSMutableDictionary dictionary];
    NSDictionary *appsJson = json[@"apps"];
    if ([appsJson isKindOfClass:NSDictionary.class]) {
        for (NSString *bundle in appsJson) {
            if ([bundle hasPrefix:@"//"]) continue;   // comment keys
            NSDictionary *c = appsJson[bundle];
            if (![c isKindOfClass:NSDictionary.class]) continue;
            AppConfig *ac = [AppConfig new];
            ac.bundleID  = bundle;
            ac.injection = [c[@"injection"] boolValue];
            ac.hiding    = [c[@"hiding"] boolValue];
            ac.dylibs    = [c[@"dylibs"] isKindOfClass:NSArray.class] ? c[@"dylibs"] : @[];
            ac.values    = [c[@"values"] isKindOfClass:NSDictionary.class] ? c[@"values"] : @{};
            apps[bundle] = ac;
        }
    }

    NSArray *global = @[];
    NSDictionary *gd = json[@"global_dylibs"];
    if ([gd isKindOfClass:NSDictionary.class] && [gd[@"paths"] isKindOfClass:NSArray.class]) {
        global = gd[@"paths"];
    }

    NSDictionary *daemon = json[@"daemon"];
    NSString *port = _portName, *logp = _logPath; NSTimeInterval poll = _poll;
    if ([daemon isKindOfClass:NSDictionary.class]) {
        if ([daemon[@"port_name"] isKindOfClass:NSString.class]) port = daemon[@"port_name"];
        if ([daemon[@"log_path"]  isKindOfClass:NSString.class]) logp = daemon[@"log_path"];
        if ([daemon[@"poll_interval_ms"] isKindOfClass:NSNumber.class])
            poll = [daemon[@"poll_interval_ms"] doubleValue] / 1000.0;
    }

    os_unfair_lock_lock(&_lock);
    [_apps setDictionary:apps];
    _globalDylibs = [global copy];
    _portName = [port copy];
    _logPath  = [logp copy];
    _poll = poll;
    NSUInteger count = _apps.count;
    os_unfair_lock_unlock(&_lock);

    TFLogI(@"ConfigLoader: loaded %lu apps, %lu global dylibs from %@",
           (unsigned long)count, (unsigned long)global.count, path);
    return YES;
}

- (AppConfig *)configForBundle:(NSString *)bundleID {
    if (bundleID.length == 0) return nil;
    os_unfair_lock_lock(&_lock);
    AppConfig *c = _apps[bundleID];
    os_unfair_lock_unlock(&_lock);
    return c;
}

- (BOOL)shouldInjectBundle:(NSString *)bundleID {
    AppConfig *c = [self configForBundle:bundleID];
    return c.injection;
}

- (NSArray<NSString *> *)dylibsForBundle:(NSString *)bundleID {
    NSMutableArray *out = [NSMutableArray array];
    os_unfair_lock_lock(&_lock);
    [out addObjectsFromArray:_globalDylibs];
    AppConfig *c = _apps[bundleID];
    if (c.dylibs) [out addObjectsFromArray:c.dylibs];
    os_unfair_lock_unlock(&_lock);
    // De-duplicate preserving order / Удаляем дубликаты сохраняя порядок
    NSMutableArray *unique = [NSMutableArray array];
    for (NSString *p in out) { if (![unique containsObject:p]) [unique addObject:p]; }
    return unique;
}

- (NSString *)valueForKey:(NSString *)key bundle:(NSString *)bundleID {
    AppConfig *c = [self configForBundle:bundleID];
    return c.values[key];
}

- (NSString *)daemonPortName { os_unfair_lock_lock(&_lock); NSString *v = _portName; os_unfair_lock_unlock(&_lock); return v; }
- (NSString *)daemonLogPath  { os_unfair_lock_lock(&_lock); NSString *v = _logPath;  os_unfair_lock_unlock(&_lock); return v; }
- (NSTimeInterval)pollInterval { os_unfair_lock_lock(&_lock); NSTimeInterval v = _poll; os_unfair_lock_unlock(&_lock); return v; }

- (BOOL)setInjection:(BOOL)enabled forBundle:(NSString *)bundleID {
    if (bundleID.length == 0) { TFLogE(@"setInjection: empty bundleID"); return NO; }
    NSString *path = [self resolveConfigPath];
    NSData *data = [NSData dataWithContentsOfFile:path];
    NSMutableDictionary *json = nil;
    if (data) {
        NSError *err = nil;
        id parsed = [NSJSONSerialization JSONObjectWithData:data options:NSJSONReadingMutableContainers error:&err];
        if ([parsed isKindOfClass:NSDictionary.class]) json = parsed;
    }
    if (!json) json = [NSMutableDictionary dictionary];

    NSMutableDictionary *apps = json[@"apps"];
    if (![apps isKindOfClass:NSMutableDictionary.class]) { apps = [NSMutableDictionary dictionary]; json[@"apps"] = apps; }
    NSMutableDictionary *app = apps[bundleID];
    if (![app isKindOfClass:NSMutableDictionary.class]) {
        app = [NSMutableDictionary dictionaryWithDictionary:@{@"injection": @NO, @"hiding": @NO, @"dylibs": @[], @"values": @{}}];
        apps[bundleID] = app;
    }
    app[@"injection"] = @(enabled);

    NSError *err = nil;
    NSData *out = [NSJSONSerialization dataWithJSONObject:json options:NSJSONWritingPrettyPrinted error:&err];
    if (!out) { TFLogE(@"setInjection: serialize failed: %@", err); return NO; }
    if (![out writeToFile:path options:NSDataWritingAtomic error:&err]) {
        TFLogE(@"setInjection: write failed to %@: %@", path, err); return NO;
    }
    [self reload];
    TFLogI(@"setInjection: %@ -> %d", bundleID, enabled);
    return YES;
}

@end
