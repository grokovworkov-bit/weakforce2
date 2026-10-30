/*
 * TweakForce — main.m (InjectionDaemon entry point / точка входа daemon)
 * EN: Wires Logger, ConfigLoader, XPCServer and ProcessMonitor together.
 *     For each new whitelisted process: try Mechanism A (pre-launch env) and
 *     Mechanism B (mach_inject) as fallback. Runs the main run loop.
 * RU: Связывает Logger, ConfigLoader, XPCServer и ProcessMonitor. Для каждого
 *     нового процесса из whitelist: Механизм A (pre-launch env) и Механизм B
 *     (mach_inject) как fallback. Запускает главный run loop.
 * BUILD: see Makefile. VERIFY: tail daemon.log, launch whitelisted app.
 */
#import <Foundation/Foundation.h>
#import "Logger.h"
#import "ConfigLoader.h"
#import "XPCServer.h"
#import "ProcessMonitor.h"
#import "InjectionEngine.h"

int main(int argc, char *argv[]) {
    @autoreleasepool {
        ConfigLoader *cfg = [ConfigLoader shared];
        [[Logger shared] setLogFilePath:cfg.daemonLogPath];
        TFLogI(@"==== TweakForce daemon starting (pid %d) ====", getpid());

        if (![[XPCServer shared] startWithPortName:cfg.daemonPortName]) {
            TFLogE(@"daemon: XPC server failed to start — exiting");
            return 1;
        }

        ProcessMonitor *mon = [[ProcessMonitor alloc] initWithPollInterval:cfg.pollInterval];
        [mon startWithHandler:^(pid_t pid, NSString *bundleID, NSString *path) {
            if (!bundleID) return;
            if (![cfg shouldInjectBundle:bundleID]) return;
            NSArray *dylibs = [cfg dylibsForBundle:bundleID];
            TFLogI(@"daemon: whitelisted launch pid=%d bundle=%@ dylibs=%lu",
                   pid, bundleID, (unsigned long)dylibs.count);

            // Mechanism A: register pre-launch env for NEXT launch (clean path).
            // Механизм A: регистрируем pre-launch env для следующего запуска.
            [[InjectionEngine shared] registerPreLaunchInjectionForBundle:bundleID dylibs:dylibs];

            // Mechanism B: inject into the already-running pid now (fallback).
            // Механизм B: внедряем в уже запущенный pid сейчас (fallback).
            TFInjectionResult r = [[InjectionEngine shared] injectIntoPid:pid bundle:bundleID dylibs:dylibs];
            TFLogI(@"daemon: inject pid=%d -> %@", pid, [InjectionEngine describeResult:r]);
        }];

        TFLogI(@"daemon: entering run loop");
        CFRunLoopRun();
    }
    return 0;
}
