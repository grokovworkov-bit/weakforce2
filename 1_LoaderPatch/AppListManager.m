/*
 * ============================================================================
 *  TweakForce — AppListManager.m
 * ============================================================================
 *  EN: Implementation. Thread-safe (os_unfair_lock). All error paths logged.
 *  RU: Реализация. Потокобезопасно (os_unfair_lock). Все ошибки логируются.
 *
 *  VERIFY / КАК ПРОВЕРИТЬ:
 *    - Call -reload, then -isInInjectionWhitelist: for a known bundle.
 *    - Toggle -setAppList:/-setHideList: and inspect the plist on disk.
 * ============================================================================
 */

#import "AppListManager.h"
#import <os/log.h>
#import <os/lock.h>

// --- Constants / Константы -------------------------------------------------
#define TF_SUBSYSTEM            "com.tweakforce"
#define TF_CATEGORY             "AppListManager"

// Keys inside com.roothide.bootstrap.plist (adjust per RootHide build).
// Ключи внутри com.roothide.bootstrap.plist (подстроить под билд RootHide).
#define TF_KEY_APP_LIST         @"appList"
#define TF_KEY_HIDE_LIST        @"hideList"

// TweakForce whitelist is stored alongside, under our own key, so it never
// collides with RootHide's own keys.
// Whitelist TweakForce хранится рядом под нашим ключом, чтобы не конфликтовать.
#define TF_KEY_TF_WHITELIST     @"tweakforceInjectionWhitelist"

// Candidate jbroot-relative locations for the bootstrap prefs.
// Кандидаты расположения настроек bootstrap относительно jbroot.
static NSString *const kBootstrapPrefCandidates[] = {
    @"/var/jb/var/mobile/Library/Preferences/com.roothide.bootstrap.plist",
    @"/var/mobile/Library/Preferences/com.roothide.bootstrap.plist",
};

static os_log_t TFALMLog(void) {
    static os_log_t l; static dispatch_once_t once;
    dispatch_once(&once, ^{ l = os_log_create(TF_SUBSYSTEM, TF_CATEGORY); });
    return l;
}
#define TFALM_LOG(fmt, ...)  os_log(TFALMLog(), fmt, ##__VA_ARGS__)
#define TFALM_ERR(fmt, ...)  os_log_error(TFALMLog(), fmt, ##__VA_ARGS__)

@implementation AppListManager {
    os_unfair_lock _lock;                 // protects the cached sets below
    NSMutableSet<NSString *> *_appList;
    NSMutableSet<NSString *> *_hideList;
    NSMutableSet<NSString *> *_whitelist;
    NSString *_resolvedPath;
}

+ (instancetype)shared {
    static AppListManager *s; static dispatch_once_t once;
    dispatch_once(&once, ^{ s = [[AppListManager alloc] init]; });
    return s;
}

- (instancetype)init {
    if ((self = [super init])) {
        _lock = OS_UNFAIR_LOCK_INIT;
        _appList   = [NSMutableSet set];
        _hideList  = [NSMutableSet set];
        _whitelist = [NSMutableSet set];
        [self reload];
    }
    return self;
}

#pragma mark - Path resolution

- (NSString *)bootstrapPrefsPath {
    if (_resolvedPath) return _resolvedPath;
    NSFileManager *fm = NSFileManager.defaultManager;
    for (size_t i = 0; i < sizeof(kBootstrapPrefCandidates)/sizeof(kBootstrapPrefCandidates[0]); i++) {
        NSString *p = kBootstrapPrefCandidates[i];
        if ([fm fileExistsAtPath:p]) {
            _resolvedPath = p;
            TFALM_LOG("[TweakForce] bootstrap prefs at %{public}@", p);
            return p;
        }
    }
    // EN: Fall back to the primary candidate even if absent (we may create it).
    // RU: Используем основной кандидат, даже если его нет (создадим при записи).
    _resolvedPath = kBootstrapPrefCandidates[0];
    TFALM_ERR("[TweakForce] bootstrap prefs not found; defaulting to %{public}@", _resolvedPath);
    return _resolvedPath;
}

#pragma mark - Reload

- (void)reload {
    NSString *path = [self bootstrapPrefsPath];
    NSDictionary *root = [NSDictionary dictionaryWithContentsOfFile:path];
    if (!root) {
        TFALM_ERR("[TweakForce] could not read plist at %{public}@ (may not exist yet)", path);
        root = @{};
    }

    NSArray *app  = [root[TF_KEY_APP_LIST]  isKindOfClass:NSArray.class] ? root[TF_KEY_APP_LIST]  : @[];
    NSArray *hide = [root[TF_KEY_HIDE_LIST] isKindOfClass:NSArray.class] ? root[TF_KEY_HIDE_LIST] : @[];
    NSArray *wl   = [root[TF_KEY_TF_WHITELIST] isKindOfClass:NSArray.class] ? root[TF_KEY_TF_WHITELIST] : @[];

    // EN: Also merge whitelist from the TweakForce JSON config (apps with injection:true).
    // RU: Также добавляем whitelist из JSON-конфига TweakForce (apps с injection:true).
    NSArray *fromConfig = [self whitelistFromTweakForceConfig];

    os_unfair_lock_lock(&_lock);
    [_appList   setSet:[NSSet setWithArray:app]];
    [_hideList  setSet:[NSSet setWithArray:hide]];
    [_whitelist setSet:[NSSet setWithArray:wl]];
    [_whitelist addObjectsFromArray:fromConfig];
    NSUInteger ac = _appList.count, hc = _hideList.count, wc = _whitelist.count;
    os_unfair_lock_unlock(&_lock);

    TFALM_LOG("[TweakForce] reloaded: appList=%lu hideList=%lu whitelist=%lu",
              (unsigned long)ac, (unsigned long)hc, (unsigned long)wc);
}

- (NSArray<NSString *> *)whitelistFromTweakForceConfig {
    NSArray *paths = @[@"/var/jb/etc/tweakforce.json",
                       @"/var/jb/var/mobile/Library/TweakForce/tweakforce.json"];
    for (NSString *p in paths) {
        NSData *d = [NSData dataWithContentsOfFile:p];
        if (!d) continue;
        NSError *err = nil;
        NSDictionary *json = [NSJSONSerialization JSONObjectWithData:d options:0 error:&err];
        if (![json isKindOfClass:NSDictionary.class]) {
            TFALM_ERR("[TweakForce] bad tweakforce.json at %{public}@: %{public}@", p, err);
            continue;
        }
        NSDictionary *apps = json[@"apps"];
        if (![apps isKindOfClass:NSDictionary.class]) continue;
        NSMutableArray *out = [NSMutableArray array];
        for (NSString *bundle in apps) {
            if ([bundle hasPrefix:@"//"]) continue; // skip comment keys
            NSDictionary *cfg = apps[bundle];
            if ([cfg isKindOfClass:NSDictionary.class] && [cfg[@"injection"] boolValue]) {
                [out addObject:bundle];
            }
        }
        TFALM_LOG("[TweakForce] whitelist from config: %lu entries", (unsigned long)out.count);
        return out;
    }
    return @[];
}

#pragma mark - Queries

- (BOOL)_contains:(NSSet *)which bundle:(NSString *)b {
    if (b.length == 0) return NO;
    os_unfair_lock_lock(&_lock);
    BOOL r = [which containsObject:b];
    os_unfair_lock_unlock(&_lock);
    return r;
}

- (BOOL)isInAppList:(NSString *)bundleID            { return [self _contains:_appList bundle:bundleID]; }
- (BOOL)isInHideList:(NSString *)bundleID           { return [self _contains:_hideList bundle:bundleID]; }
- (BOOL)isInInjectionWhitelist:(NSString *)bundleID { return [self _contains:_whitelist bundle:bundleID]; }

#pragma mark - Mutations

// EN: Generic on-disk mutation helper. Reads, mutates one array key, writes back.
// RU: Общий помощник записи. Читает, меняет один массив-ключ, пишет обратно.
- (BOOL)_setMembership:(BOOL)enabled bundle:(NSString *)bundleID key:(NSString *)key cache:(NSMutableSet *)cache {
    if (bundleID.length == 0) {
        TFALM_ERR("[TweakForce] empty bundleID for key %{public}@", key);
        return NO;
    }
    NSString *path = [self bootstrapPrefsPath];
    NSMutableDictionary *root = [[NSMutableDictionary alloc] initWithContentsOfFile:path] ?: [NSMutableDictionary dictionary];
    NSMutableArray *arr = [([root[key] isKindOfClass:NSArray.class] ? root[key] : @[]) mutableCopy];

    BOOL present = [arr containsObject:bundleID];
    if (enabled && !present)      { [arr addObject:bundleID]; }
    else if (!enabled && present) { [arr removeObject:bundleID]; }
    else { /* already in desired state */ }

    root[key] = arr;
    NSError *err = nil;
    NSData *data = [NSPropertyListSerialization dataWithPropertyList:root
                                                             format:NSPropertyListBinaryFormat_v1_0
                                                            options:0 error:&err];
    if (!data) {
        TFALM_ERR("[TweakForce] serialize failed for %{public}@: %{public}@", key, err);
        return NO;
    }
    if (![data writeToFile:path options:NSDataWritingAtomic error:&err]) {
        TFALM_ERR("[TweakForce] write failed to %{public}@: %{public}@", path, err);
        return NO;
    }

    os_unfair_lock_lock(&_lock);
    if (enabled) [cache addObject:bundleID]; else [cache removeObject:bundleID];
    os_unfair_lock_unlock(&_lock);

    TFALM_LOG("[TweakForce] %{public}@ %{public}@ -> %d", key, bundleID, enabled);
    return YES;
}

- (BOOL)setAppList:(BOOL)enabled forBundle:(NSString *)bundleID {
    return [self _setMembership:enabled bundle:bundleID key:TF_KEY_APP_LIST cache:_appList];
}
- (BOOL)setHideList:(BOOL)enabled forBundle:(NSString *)bundleID {
    return [self _setMembership:enabled bundle:bundleID key:TF_KEY_HIDE_LIST cache:_hideList];
}
- (BOOL)setInjectionWhitelist:(BOOL)enabled forBundle:(NSString *)bundleID {
    return [self _setMembership:enabled bundle:bundleID key:TF_KEY_TF_WHITELIST cache:_whitelist];
}

@end
