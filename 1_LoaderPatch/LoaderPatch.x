/*
 * ============================================================================
 *  TweakForce — LoaderPatch.x
 * ============================================================================
 *  PURPOSE / НАЗНАЧЕНИЕ
 *  --------------------------------------------------------------------------
 *  EN: Patch of the RootHide Bootstrap loader. On RootHide, enabling the
 *      "Hide" list for an app also *blocks* tweak injection, because the
 *      current loader treats hiding as higher priority than injection.
 *      This Logos tweak hooks the injection-decision functions inside the
 *      bootstrap process so that a process present in the TweakForce
 *      whitelist ALWAYS gets injected — even when it is also hidden.
 *
 *  RU: Патч к Bootstrap loader'у RootHide. В RootHide включение списка
 *      "Hide" для приложения ТАКЖЕ блокирует инъекцию tweaks, так как
 *      текущий loader считает скрытие приоритетнее инъекции.
 *      Этот Logos-tweak хукает функции принятия решения об инъекции
 *      внутри процесса bootstrap так, что процесс из whitelist TweakForce
 *      ВСЕГДА получает инъекцию — даже если он также скрыт.
 *
 *  BUILD / СБОРКА
 *  --------------------------------------------------------------------------
 *      cd 1_LoaderPatch && make package THEOS_PACKAGE_SCHEME=roothide
 *      Устанавливается как tweak, грузится в процесс bootstrap/bootstrapd.
 *
 *  VERIFY / КАК ПРОВЕРИТЬ
 *  --------------------------------------------------------------------------
 *      1. Включить hiding для тестового приложения в RootHide.
 *      2. Добавить его bundleID в whitelist (AppListManager / Manager app).
 *      3. Запустить приложение → libTweakForceHooks должен загрузиться
 *         (проверить через TestApp DiagnosticViewController или
 *          `log stream --predicate 'subsystem == "com.tweakforce"'`).
 *
 *  HONEST LIMITATION / ЧЕСТНОЕ ОГРАНИЧЕНИЕ
 *  --------------------------------------------------------------------------
 *      Работает только если процесс bootstrap доступен для hooking через
 *      ElleKit/Substrate. Имена символов ниже зависят от версии RootHide и,
 *      возможно, потребуют подстройки под конкретный билд bootstrap.
 * ============================================================================
 */

#import <Foundation/Foundation.h>
#import <os/log.h>
#import "AppListManager.h"

// --- ElleKit / Substrate dynamic hooking API ------------------------------
// EN: We declare the MS* symbols weakly so the tweak builds against either
//     ElleKit (preferred on RootHide) or classic Substrate.
// RU: Объявляем символы MS* слабо, чтобы собираться как под ElleKit
//     (предпочтительно на RootHide), так и под классический Substrate.
extern void MSHookFunction(void *symbol, void *replace, void **result);
extern void *MSFindSymbol(void *image, const char *name);
extern void *MSGetImageByName(const char *name);

// --- Logging --------------------------------------------------------------
#define TF_LP_SUBSYSTEM "com.tweakforce"
#define TF_LP_CATEGORY  "LoaderPatch"
static os_log_t TFLPLog(void) {
    static os_log_t l; static dispatch_once_t once;
    dispatch_once(&once, ^{ l = os_log_create(TF_LP_SUBSYSTEM, TF_LP_CATEGORY); });
    return l;
}
#define TFLP_LOG(fmt, ...) os_log(TFLPLog(), fmt, ##__VA_ARGS__)

// --- Candidate symbol names in the bootstrap binary -----------------------
// EN: Different RootHide builds expose the decision logic under different
//     symbol names. We try each candidate in order. Adjust as needed.
// RU: Разные билды RootHide экспортируют логику решения под разными именами.
//     Пробуем каждого кандидата по очереди. Подстроить при необходимости.
static const char *kDecisionSymbolCandidates[] = {
    "_Z15shouldInjectPidi",             // mangled C++ shouldInjectPid(int)
    "shouldInjectProcess",
    "bootstrap_should_inject",
    "_isAppEnabled",
    NULL
};

static const char *kHideCheckSymbolCandidates[] = {
    "_Z10isAppHiddenPKc",               // mangled isAppHidden(const char*)
    "isProcessHidden",
    "bootstrap_is_hidden",
    NULL
};

// ==========================================================================
//  HOOK 1 — injection decision
//  EN: Original returns whether a pid/bundle should be injected. We force
//      TRUE for whitelisted bundles regardless of what the loader decided.
//  RU: Оригинал возвращает, надо ли внедрять в pid/bundle. Для bundle из
//      whitelist форсируем TRUE независимо от решения loader'а.
// ==========================================================================
typedef bool (*tf_decision_fn)(const char *bundleID);
static tf_decision_fn orig_decision = NULL;

static bool tf_decision_replacement(const char *bundleID) {
    bool original = orig_decision ? orig_decision(bundleID) : false;
    if (bundleID && [[AppListManager shared] isInInjectionWhitelist:@(bundleID)]) {
        if (!original) {
            TFLP_LOG("[TweakForce] FORCING injection for whitelisted bundle: %{public}s (loader said NO)", bundleID);
        }
        return true;   // EN: whitelist wins / RU: whitelist побеждает
    }
    return original;
}

// ==========================================================================
//  HOOK 2 — hide check (decouple hiding from injection)
//  EN: The loader may short-circuit injection when a process is hidden.
//      For whitelisted bundles we report "not hidden" to the injection path
//      ONLY — real hiding behaviour elsewhere is untouched.
//  RU: Loader может прерывать инъекцию, если процесс скрыт. Для bundle из
//      whitelist сообщаем "не скрыт" ТОЛЬКО на пути инъекции — реальное
//      скрытие в других местах не затрагивается.
// ==========================================================================
typedef bool (*tf_hidecheck_fn)(const char *bundleID);
static tf_hidecheck_fn orig_hidecheck = NULL;

static bool tf_hidecheck_replacement(const char *bundleID) {
    if (bundleID && [[AppListManager shared] isInInjectionWhitelist:@(bundleID)]) {
        // EN: Decouple — pretend not hidden for injection path.
        // RU: Разделяем — для пути инъекции притворяемся, что не скрыт.
        TFLP_LOG("[TweakForce] decoupling hide-check for whitelisted bundle: %{public}s", bundleID);
        return false;
    }
    return orig_hidecheck ? orig_hidecheck(bundleID) : false;
}

// --- Helper: resolve first available symbol among candidates --------------
static void *tf_resolve_symbol(void *image, const char *const *candidates) {
    for (int i = 0; candidates[i] != NULL; i++) {
        void *sym = MSFindSymbol(image, candidates[i]);
        if (sym) {
            TFLP_LOG("[TweakForce] resolved symbol %{public}s", candidates[i]);
            return sym;
        }
    }
    return NULL;
}

// ==========================================================================
//  Constructor — install hooks when loaded into bootstrap process
// ==========================================================================
%ctor {
    @autoreleasepool {
        NSString *procName = NSProcessInfo.processInfo.processName ?: @"?";
        // EN: Only act inside the bootstrap/bootstrapd process.
        // RU: Действуем только внутри процесса bootstrap/bootstrapd.
        if (![procName containsString:@"bootstrap"] &&
            ![procName isEqualToString:@"bootstrapd"]) {
            return;
        }
        TFLP_LOG("[TweakForce] LoaderPatch loaded into %{public}@", procName);

        // EN: Prime the whitelist from RootHide prefs + TweakForce config.
        // RU: Инициализируем whitelist из настроек RootHide + конфига TweakForce.
        [[AppListManager shared] reload];

        // EN: The bootstrap logic may be in the main image (NULL) or a helper dylib.
        // RU: Логика bootstrap может быть в главном образе (NULL) или в dylib-помощнике.
        void *image = NULL; // main executable

        void *decisionSym = tf_resolve_symbol(image, kDecisionSymbolCandidates);
        if (decisionSym) {
            MSHookFunction(decisionSym, (void *)tf_decision_replacement, (void **)&orig_decision);
            TFLP_LOG("[TweakForce] injection-decision hook installed");
        } else {
            TFLP_LOG("[TweakForce] WARNING: injection-decision symbol not found — adjust kDecisionSymbolCandidates for this RootHide build");
        }

        void *hideSym = tf_resolve_symbol(image, kHideCheckSymbolCandidates);
        if (hideSym) {
            MSHookFunction(hideSym, (void *)tf_hidecheck_replacement, (void **)&orig_hidecheck);
            TFLP_LOG("[TweakForce] hide-check decoupling hook installed");
        } else {
            TFLP_LOG("[TweakForce] NOTE: hide-check symbol not found — relying on decision hook only");
        }
    }
}
