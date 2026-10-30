/*
 * ============================================================================
 *  TweakForce — AppListManager.h
 * ============================================================================
 *  EN: Reads/writes the RootHide bootstrap preferences
 *      (com.roothide.bootstrap.plist) which hold the App List and Hide List,
 *      and maintains an independent TweakForce injection whitelist.
 *      Lets you add a bundle to App List and Hide List INDEPENDENTLY.
 *  RU: Читает/пишет настройки bootstrap RootHide
 *      (com.roothide.bootstrap.plist), где хранятся App List и Hide List,
 *      и ведёт независимый whitelist инъекции TweakForce.
 *      Позволяет добавлять bundle в App List и Hide List НЕЗАВИСИМО.
 *
 *  BUILD: part of 1_LoaderPatch (compiled into the tweak dylib).
 * ============================================================================
 */

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface AppListManager : NSObject

/// Shared singleton / Общий синглтон
+ (instancetype)shared;

/// Reload lists from disk (RootHide prefs + TweakForce config).
/// Перечитать списки с диска (настройки RootHide + конфиг TweakForce).
- (void)reload;

#pragma mark - Queries / Запросы

/// Is bundleID in RootHide App List? / Есть ли bundleID в App List RootHide?
- (BOOL)isInAppList:(NSString *)bundleID;

/// Is bundleID in RootHide Hide List? / Есть ли bundleID в Hide List RootHide?
- (BOOL)isInHideList:(NSString *)bundleID;

/// Is bundleID in the TweakForce injection whitelist (highest priority)?
/// Есть ли bundleID в whitelist инъекции TweakForce (высший приоритет)?
- (BOOL)isInInjectionWhitelist:(NSString *)bundleID;

#pragma mark - Mutations / Изменения

/// Add/remove bundleID to/from App List independently.
/// Добавить/убрать bundleID в/из App List независимо.
- (BOOL)setAppList:(BOOL)enabled forBundle:(NSString *)bundleID;

/// Add/remove bundleID to/from Hide List independently.
/// Добавить/убрать bundleID в/из Hide List независимо.
- (BOOL)setHideList:(BOOL)enabled forBundle:(NSString *)bundleID;

/// Add/remove bundleID to/from the TweakForce injection whitelist.
/// Добавить/убрать bundleID в/из whitelist инъекции TweakForce.
- (BOOL)setInjectionWhitelist:(BOOL)enabled forBundle:(NSString *)bundleID;

#pragma mark - Paths / Пути

/// Resolved path to com.roothide.bootstrap.plist (jbroot-aware).
/// Разрешённый путь к com.roothide.bootstrap.plist (с учётом jbroot).
- (NSString *)bootstrapPrefsPath;

@end

NS_ASSUME_NONNULL_END
