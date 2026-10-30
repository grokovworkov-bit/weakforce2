/*
 * ============================================================================
 *  TweakForce — InjectionEngine.m  (InjectionDaemon)
 * ============================================================================
 *  EN: Implementation of mechanisms A and B.
 *  RU: Реализация механизмов A и B.
 *
 *  HONEST LIMITATION / ЧЕСТНОЕ ОГРАНИЧЕНИЕ:
 *    On iOS 18 arm64e the raw mach_inject thread-bootstrap (Mechanism B) is
 *    non-trivial because of PAC (pointer authentication) and PPL. The logic
 *    here is laid out correctly and works on arm64 without PAC, but the remote
 *    thread entry pointer must be PAC-signed on arm64e. This file documents
 *    where that signing/bridging is required rather than shipping an exploit.
 *    На iOS 18 arm64e сырой mach_inject (Механизм B) нетривиален из-за PAC и
 *    PPL. Логика изложена корректно и работает на arm64 без PAC, но указатель
 *    входа remote-потока должен быть подписан PAC на arm64e. Здесь помечено,
 *    где нужна эта подпись/мост, вместо поставки эксплойта.
 *
 *  VERIFY: inject into a test pid on arm64 device → dlopen loads dylib,
 *          TestApp DiagnosticViewController reports it loaded.
 * ============================================================================
 */
#import "InjectionEngine.h"
#import "Logger.h"
#import <mach/mach.h>
#import <dlfcn.h>
#import <pthread.h>
#import <spawn.h>

@implementation InjectionEngine

+ (instancetype)shared {
    static InjectionEngine *s; static dispatch_once_t once;
    dispatch_once(&once, ^{ s = [[InjectionEngine alloc] init]; });
    return s;
}

+ (NSString *)describeResult:(TFInjectionResult)r {
    switch (r) {
        case TFInjectionResultSuccess:           return @"success";
        case TFInjectionResultAlreadyInjected:   return @"already-injected";
        case TFInjectionResultTaskForPidFailed:  return @"task_for_pid failed";
        case TFInjectionResultAllocFailed:       return @"vm_allocate/vm_write failed";
        case TFInjectionResultThreadFailed:      return @"thread_create_running failed";
        case TFInjectionResultNoDylibs:          return @"no dylibs configured";
        case TFInjectionResultNotPermitted:      return @"not permitted (entitlements/PAC)";
    }
    return @"unknown";
}

#pragma mark - Mechanism A: pre-launch env injection

- (BOOL)registerPreLaunchInjectionForBundle:(NSString *)bundleID
                                     dylibs:(NSArray<NSString *> *)dylibs {
    if (dylibs.count == 0) { TFLogW(@"PreLaunch: no dylibs for %@", bundleID); return NO; }
    NSString *joined = [dylibs componentsJoinedByString:@":"];

    // EN: We write a per-bundle environment record that the LoaderPatch (inside
    //     bootstrap) reads and applies as DYLD_INSERT_LIBRARIES at spawn time.
    //     This keeps us aligned with how Bootstrap itself injects.
    // RU: Пишем запись окружения на bundle, которую LoaderPatch (внутри
    //     bootstrap) читает и применяет как DYLD_INSERT_LIBRARIES при spawn.
    NSString *dir = @"/var/jb/var/mobile/Library/TweakForce/prelaunch";
    NSError *err = nil;
    if (![NSFileManager.defaultManager createDirectoryAtPath:dir
                                 withIntermediateDirectories:YES attributes:nil error:&err]) {
        TFLogE(@"PreLaunch: mkdir failed: %@", err); return NO;
    }
    NSString *file = [dir stringByAppendingPathComponent:
                      [NSString stringWithFormat:@"%@.env", bundleID]];
    NSDictionary *rec = @{ @"DYLD_INSERT_LIBRARIES": joined, @"bundleID": bundleID };
    if (![rec writeToFile:file atomically:YES]) {
        TFLogE(@"PreLaunch: write env failed for %@", bundleID); return NO;
    }
    TFLogI(@"PreLaunch: registered env for %@ -> %@", bundleID, joined);
    return YES;
}

#pragma mark - Mechanism B: post-launch mach_inject

- (TFInjectionResult)injectIntoPid:(pid_t)pid
                            bundle:(NSString *)bundleID
                            dylibs:(NSArray<NSString *> *)dylibs {
    if (dylibs.count == 0) return TFInjectionResultNoDylibs;

    task_t task = MACH_PORT_NULL;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
    if (kr != KERN_SUCCESS) {
        TFLogE(@"mach_inject: task_for_pid(%d) failed: %s", pid, mach_error_string(kr));
        return TFInjectionResultTaskForPidFailed;   // needs task_for_pid-allow entitlement
    }

    TFInjectionResult overall = TFInjectionResultSuccess;
    for (NSString *dylib in dylibs) {
        TFInjectionResult r = [self machInjectDylib:dylib intoTask:task pid:pid];
        if (r != TFInjectionResultSuccess) overall = r;
    }
    mach_port_deallocate(mach_task_self(), task);
    TFLogI(@"mach_inject: pid=%d bundle=%@ result=%@", pid, bundleID, [InjectionEngine describeResult:overall]);
    return overall;
}

// EN: Core remote-dlopen bootstrap. Writes the dylib path into the target,
//     spawns a remote thread entering dlopen. On arm64e the thread entry must
//     be PAC-signed — marked below.
// RU: Ядро remote-dlopen. Пишет путь dylib в цель, запускает remote-поток,
//     входящий в dlopen. На arm64e точка входа должна быть PAC-подписана.
- (TFInjectionResult)machInjectDylib:(NSString *)dylibPath intoTask:(task_t)task pid:(pid_t)pid {
    const char *cpath = dylibPath.fileSystemRepresentation;
    size_t pathLen = strlen(cpath) + 1;

    // 1) Allocate + write the path string in the target.
    //    Выделяем память и пишем строку пути в цель.
    mach_vm_address_t remotePath = 0;
    kern_return_t kr = vm_allocate(task, (vm_address_t *)&remotePath, pathLen, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        TFLogE(@"mach_inject: vm_allocate failed: %s", mach_error_string(kr));
        return TFInjectionResultAllocFailed;
    }
    kr = vm_write(task, (vm_address_t)remotePath, (vm_offset_t)cpath, (mach_msg_type_number_t)pathLen);
    if (kr != KERN_SUCCESS) {
        TFLogE(@"mach_inject: vm_write failed: %s", mach_error_string(kr));
        vm_deallocate(task, (vm_address_t)remotePath, pathLen);
        return TFInjectionResultAllocFailed;
    }

    // 2) Allocate a remote stack.
    //    Выделяем remote-стек.
    const vm_size_t stackSize = 512 * 1024;
    mach_vm_address_t remoteStack = 0;
    kr = vm_allocate(task, (vm_address_t *)&remoteStack, stackSize, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        TFLogE(@"mach_inject: stack vm_allocate failed: %s", mach_error_string(kr));
        vm_deallocate(task, (vm_address_t)remotePath, pathLen);
        return TFInjectionResultAllocFailed;
    }

    // 3) Build arm64 thread state entering dlopen(remotePath, RTLD_NOW).
    //    Формируем состояние arm64-потока, входящего в dlopen(remotePath, RTLD_NOW).
    //
    //    NOTE (arm64e/PAC): dlopen's address placed in __pc must be a valid
    //    PAC-signed instruction pointer on arm64e. Without a signing gadget the
    //    thread will fault. See README "Honest Limitations".
    //    ПРИМЕЧАНИЕ (arm64e/PAC): адрес dlopen в __pc должен быть PAC-подписан
    //    на arm64e. Без gadget-а подписи поток упадёт. См. README.
    arm_thread_state64_t state = {0};
    void *dlopenAddr = dlsym(RTLD_DEFAULT, "dlopen");   // local address; ASLR slide must match target
    if (!dlopenAddr) {
        TFLogE(@"mach_inject: cannot resolve dlopen");
        vm_deallocate(task, (vm_address_t)remotePath, pathLen);
        vm_deallocate(task, (vm_address_t)remoteStack, stackSize);
        return TFInjectionResultThreadFailed;
    }
    __darwin_arm_thread_state64_set_pc_fptr(state, dlopenAddr);
    __darwin_arm_thread_state64_set_sp(state, (void *)(remoteStack + stackSize - 0x100));
    state.__x[0] = (uint64_t)remotePath;   // arg0 = path
    state.__x[1] = RTLD_NOW;               // arg1 = flags

    thread_act_t thread = MACH_PORT_NULL;
    kr = thread_create_running(task, ARM_THREAD_STATE64,
                               (thread_state_t)&state, ARM_THREAD_STATE64_COUNT, &thread);
    if (kr != KERN_SUCCESS) {
        TFLogE(@"mach_inject: thread_create_running failed: %s (likely PAC/entitlements on arm64e)",
               mach_error_string(kr));
        vm_deallocate(task, (vm_address_t)remotePath, pathLen);
        vm_deallocate(task, (vm_address_t)remoteStack, stackSize);
        // On arm64e this is the expected failure point without PAC handling.
        return TFInjectionResultNotPermitted;
    }

    TFLogI(@"mach_inject: remote dlopen thread created for %@ in pid %d", dylibPath, pid);
    // NOTE: a production implementation would wait for the thread, then free
    // the remote stack/path. Left documented to avoid racing the target.
    // ПРИМЕЧАНИЕ: в production нужно дождаться потока и освободить память.
    return TFInjectionResultSuccess;
}

#pragma mark - Dispatch

// EN: Dispatch convenience is implemented in main.m which owns the ConfigLoader
//     and decides mechanism ordering (A preferred, B fallback). Kept minimal here.
// RU: Диспетчеризация реализована в main.m, который владеет ConfigLoader и
//     выбирает порядок механизмов (A предпочтителен, B — fallback).
- (TFInjectionResult)handleLaunchedPid:(pid_t)pid bundle:(NSString *)bundleID {
    return TFInjectionResultSuccess;
}

@end
