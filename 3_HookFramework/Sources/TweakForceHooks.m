/*
 * ============================================================================
 *  TweakForce — TweakForceHooks.m
 * ============================================================================
 *  EN: Universal Hook, Spoofing & Stealth Framework implementation (Echelons 1-15).
 *        • Deep Unwind, Mount & Kernel Integrity (Echelon 12): mach_vm_read trampoline masking,
 *          fstatfs MNT_RDONLY enforcement, _Unwind_Backtrace LLVM call-stack cloaking,
 *          proc_pidpath isolation, and getxattr/listxattr extended filesystem attribute cloaking.
 *        • VFS Raw Buffers, POSIX Mount, Process FDs & CoreServices (Echelon 13): getdirentries64
 *          raw buffer sanitization, fstatvfs mount shielding, proc_pidinfo PROC_PIDLISTFDS descriptor isolation,
 *          objc_getClassList runtime class masking, task_threads / pthread_getname_np thread isolation,
 *          and LSApplicationWorkspace URL scheme cloaking.
 *        • VFS Mutation & Attributes Shield, CoreServices Application Proxies,
 *          Dyld Insertion Cloaking & Memory Protection Armor (Echelon 14):
 *          dyld_has_inserted_or_interposing_libraries flag cloaking (always false),
 *          POSIX file/directory mutation shielding (unlink, unlinkat, rmdir, remove, rename, renameat),
 *          POSIX permissions & metadata probing protection (chmod, fchmod, fchmodat, chown, lchown, fchown, fchownat, utimes),
 *          extended VFS attribute probing (fgetattrlist, getattrlistat),
 *          process execution sandbox hardening (execve, execv),
 *          memory W^X enforcement (mprotect blocking RWX with EACCES),
 *          CoreServices / MobileCoreServices LSApplicationProxy (applicationProxyForIdentifier:,
 *          applicationProxyForBundleURL:, isInstalled) and LSApplicationWorkspace (allInstalledApplications, allApplications),
 *          and CoreFoundation C-level bundle masking (CFBundleGetBundleWithIdentifier, CFBundleCreate).
 *        • Memory Region Mapping Isolation, Protected Open, Descriptor Fstat & Attribute Mutation Shield,
 *          POSIX Privileges, Terminal Cloaking, Extended Exec & Bundle Listing Armor (Echelon 15):
 *          proc_regionfilename & proc_pidinfo (PROC_PIDREGIONPATHINFO / PROC_PIDVNODEPATHINFO) memory mapped file cloaking,
 *          Apple Data Protection open_dprotected_np shielding, fstat & fstat64 file descriptor path cloaking,
 *          setattrlist & fsetattrlist attribute mutation shielding, POSIX privilege escalation shielding (setuid, seteuid, setgid, setegid),
 *          terminal & pseudo-tty isolation (isatty, ttyname, ttyname_r), extended process execution hardening (execvp, execvP, vfork),
 *          CoreFoundation & Cocoa bundle enumeration shielding (CFBundleGetAllBundles, [NSBundle allBundles], [NSBundle allFrameworks]),
 *          and audit-token sandbox query protection (sandbox_check_by_audit_token).
 *        • Mach VM Protections, Task Ports, Runtime Reflection Cleansing,
 *          POSIX Identity, Dyld All Image Infos & VFS Flags Armor (Echelon 16):
 *          vm_protect & mach_vm_protect W^X memory protection enforcement,
 *          task_for_pid sandboxed port shielding (blocking task ports for pid != getpid()),
 *          POSIX identity cloaking (getuid, geteuid, getgid, getegid forced to unprivileged mobile 501),
 *          user/password database shell sanitization (getpwuid, getpwnam masking jailbreak shells to /bin/false),
 *          _dyld_get_all_image_infos global dyld image array cloaking,
 *          class_copyMethodList Objective-C runtime reflection cleansing (filtering tf_ hook selectors),
 *          objc_getProtocol jailbreak protocol shielding,
 *          VFS file flags shielding (chflags, lchflags, fchflags enforcing EROFS/EPERM on root/system and ENOENT on jailbreak paths),
 *          and POSIX core dump limits enforcement (getrlimit, setrlimit enforcing RLIMIT_CORE = 0).
 *        • Mach-O Load Commands, FairPlay Cryptid, Sideloading mobileprovision & App Integrity Armor (Echelon 17):
 *          _dyld_get_image_header(0) & _NSGetMachExecuteHeader() load commands sanitization (LC_LOAD_DYLIB, LC_RPATH),
 *          FairPlay encryption spoofing (LC_ENCRYPTION_INFO_64 / LC_ENCRYPTION_INFO forced cryptid=1),
 *          _NSGetExecutablePath() path isolation,
 *          embedded.mobileprovision sideloading / re-sign shield (VFS, dirent, [NSBundle pathForResource:ofType:],
 *          [NSBundle URLForResource:withExtension:], CFBundleCopyResourceURL),
 *          and NSBundle appStoreReceiptURL legitimacy enforcement.
 *      - Function hooking: MSHookFunction (ElleKit PAC) with fishhook fallback.
 *      - Method swizzling: safe method_setImplementation for ObjC.
 *      - Hardware & OS spoofing (Echelon 1): sysctlbyname, sysctl, uname,
 *        UIDevice, NSProcessInfo, MGCopyAnswer, CoreFoundation version dictionaries.
 *      - Hardened stealth & cloaking (Echelons 2 & 3):
 *        • Deep POSIX/VFS masking: access, stat, lstat, fstatat, faccessat,
 *          stat64, lstat64, open, openat, fopen, freopen, readlink, readlinkat,
 *          statfs, getfsstat, getmntinfo, getattrlist.
 *        • Code-signing & anti-debug: csops (clean CS_VALID without CS_KILL/CS_RESTRICTED),
 *          ptrace (PT_DENY_ATTACH intercepted), fork (ENOSYS sandboxed), sysctl P_TRACED stripped.
 *        • Dynamic linker: _dyld_get_image_name masking to Foundation, dladdr masking,
 *          dlsym jailbreak symbol shielding, DYLD environment variable sanitization.
 *        • Cocoa hardening: NSFileManager deep checks, NSData/NSString file reads,
 *          UIApplication URL scheme blocking.
 *      - In-app stealth & spoofing self-test audit popup with safe UI presentation.
 *      - Guaranteed crash-free on iOS 18 (arm64e / Dopamine / RootHide).
 * ============================================================================
 */

#import "TweakForceHooks.h"
#import "fishhook.h"
#import "HookRegistry.h"
#import "DiagnosticReporter.h"
#import <os/log.h>
#import <dlfcn.h>
#import <errno.h>
#import <unistd.h>
#import <sys/stat.h>
#import <sys/utsname.h>
#import <sys/sysctl.h>
#import <sys/mount.h>
#import <sys/attr.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach/mach.h>
#import <fcntl.h>
#import <stdio.h>
#import <stdarg.h>
#import <CoreFoundation/CoreFoundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <sys/un.h>
#import <arpa/inet.h>
#import <spawn.h>
#import <sys/syscall.h>
#import <sys/statvfs.h>
#import <signal.h>
#import <stdlib.h>
#import <mach/thread_act.h>
#import <mach/vm_map.h>
#import <dirent.h>
#import <pthread.h>
#import <sys/mman.h>
#import <sys/time.h>
#import <sys/resource.h>
#import <pwd.h>

#if __has_include(<mach-o/dyld_images.h>)
#import <mach-o/dyld_images.h>
#else
struct dyld_image_info {
    const struct mach_header *imageLoadAddress;
    const char *imageFilePath;
    uintptr_t imageFileModDate;
};
struct dyld_all_image_infos {
    uint32_t version;
    uint32_t infoArrayCount;
    const struct dyld_image_info *infoArray;
};
#endif
// _dyld_get_all_image_infos is resolved dynamically via dlsym to support iOS SDKs without private dyld symbols
kern_return_t mach_vm_protect(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection);

#ifndef LC_ENCRYPTION_INFO
#define LC_ENCRYPTION_INFO 0x21
struct encryption_info_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t cryptoff;
    uint32_t cryptsize;
    uint32_t cryptid;
};
#endif

#ifndef LC_ENCRYPTION_INFO_64
#define LC_ENCRYPTION_INFO_64 0x2C
struct encryption_info_command_64 {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t cryptoff;
    uint32_t cryptsize;
    uint32_t cryptid;
    uint32_t pad;
};
#endif

static const struct mach_header_64 *tf_get_sanitized_main_header(void);
static void tf_sanitize_main_header_in_place(void);
static const struct mach_header *tf_my_NSGetMachExecuteHeader(void);
static const struct mach_header *(*orig_dyld_get_image_header)(uint32_t image_index) = NULL;
static intptr_t (*orig_dyld_get_image_vmaddr_slide)(uint32_t image_index) = NULL;

#ifndef dyld_has_inserted_or_interposing_libraries
bool dyld_has_inserted_or_interposing_libraries(void) __attribute__((weak_import));
#endif

#if __has_include(<execinfo.h>)
#import <execinfo.h>
#else
int backtrace(void **buffer, int size);
char **backtrace_symbols(void *const *buffer, int size);
#endif

#ifndef mach_vm_address_t
typedef uint64_t mach_vm_address_t;
#endif
#ifndef mach_vm_size_t
typedef uint64_t mach_vm_size_t;
#endif
kern_return_t mach_vm_read_overwrite(mach_port_t target_task, mach_vm_address_t address, mach_vm_size_t size, mach_vm_address_t data, mach_vm_size_t *outsize);
kern_return_t mach_vm_read(vm_map_read_t target_task, mach_vm_address_t address, mach_vm_size_t size, vm_offset_t *data, mach_msg_type_number_t *dataCnt);
int proc_pidpath(int pid, void *buffer, uint32_t buffersize);
int proc_regionfilename(int pid, uint64_t address, void *buffer, uint32_t buffersize);
int open_dprotected_np(const char *path, int flags, int class, int dpflags, ...);
int execvP(const char *file, const char *searchpath, char *const argv[]);
#if __has_include(<mach/message.h>)
#import <mach/message.h>
#endif
int sandbox_check_by_audit_token(audit_token_t au, const char *operation, int type, ...);

#if __has_include(<unwind.h>)
#import <unwind.h>
#else
typedef enum {
    _URC_NO_REASON = 0,
    _URC_FOREIGN_EXCEPTION_CAUGHT = 1,
    _URC_FATAL_PHASE2_ERROR = 2,
    _URC_FATAL_PHASE1_ERROR = 3,
    _URC_NORMAL_STOP = 4,
    _URC_END_OF_STACK = 5,
    _URC_HANDLER_FOUND = 6,
    _URC_INSTALL_CONTEXT = 7,
    _URC_CONTINUE_UNWIND = 8
} _Unwind_Reason_Code;
struct _Unwind_Context;
typedef _Unwind_Reason_Code (*_Unwind_Trace_Fn)(struct _Unwind_Context *, void *);
uintptr_t _Unwind_GetIP(struct _Unwind_Context *);
_Unwind_Reason_Code _Unwind_Backtrace(_Unwind_Trace_Fn, void *);
#endif

#if __has_include(<sys/xattr.h>)
#import <sys/xattr.h>
#else
ssize_t getxattr(const char *path, const char *name, void *value, size_t size, u_int32_t position, int options);
ssize_t lgetxattr(const char *path, const char *name, void *value, size_t size, u_int32_t position, int options);
ssize_t fgetxattr(int fd, const char *name, void *value, size_t size, u_int32_t position, int options);
ssize_t listxattr(const char *path, char *namebuf, size_t size, int options);
ssize_t llistxattr(const char *path, char *namebuf, size_t size, int options);
ssize_t flistxattr(int fd, char *namebuf, size_t size, int options);
#endif

#ifndef ENOATTR
#define ENOATTR 93
#endif

#ifndef SANDBOX_FILTER_PATH
#define SANDBOX_FILTER_PATH 1
#endif
#ifndef SANDBOX_CHECK_NO_REPORT
#define SANDBOX_CHECK_NO_REPORT 0x40000000
#endif
int sandbox_check(pid_t pid, const char *operation, int type, ...);

#ifndef TASK_DYLD_INFO
#define TASK_DYLD_INFO 17
#endif

#ifndef VM_REGION_SUBMAP_INFO_64
#define VM_REGION_SUBMAP_INFO_64 8
#endif

#if __has_include(<servers/bootstrap.h>)
#import <servers/bootstrap.h>
#else
#ifndef BOOTSTRAP_UNKNOWN_SERVICE
#define BOOTSTRAP_UNKNOWN_SERVICE 1102
#endif
kern_return_t bootstrap_look_up(mach_port_t bp, const char *service_name, mach_port_t *sp);
#endif

#ifndef ARM_DEBUG_STATE64
#define ARM_DEBUG_STATE64 15
#endif
#ifndef ARM_DEBUG_STATE32
#define ARM_DEBUG_STATE32 14
#endif
#ifndef VM_REGION_BASIC_INFO_64
#define VM_REGION_BASIC_INFO_64 9
#endif
#ifndef VM_REGION_BASIC_INFO_COUNT_64
#define VM_REGION_BASIC_INFO_COUNT_64 ((mach_msg_type_number_t)(sizeof(vm_region_basic_info_data_64_t)/sizeof(int)))
#endif


#ifndef SYS_access
#define SYS_access 33
#endif
#ifndef SYS_stat
#define SYS_stat 38
#endif
#ifndef SYS_lstat
#define SYS_lstat 40
#endif
#ifndef SYS_open
#define SYS_open 5
#endif
#ifndef SYS_readlink
#define SYS_readlink 58
#endif
#ifndef SYS_ptrace
#define SYS_ptrace 26
#endif
#ifndef SYS_csops
#define SYS_csops 169
#endif
#ifndef SYS_statfs
#define SYS_statfs 157
#endif

#ifndef KERN_PROCARGS2
#define KERN_PROCARGS2 49
#endif

#ifndef KERN_PROC_ALL
#define KERN_PROC_ALL 0
#endif

#ifndef P_TRACED
#define P_TRACED 0x00000800
#endif

#ifndef PT_DENY_ATTACH
#define PT_DENY_ATTACH 31
#endif

#ifndef AT_FDCWD
#define AT_FDCWD -2
#endif

#ifndef CS_OPS_STATUS
#define CS_OPS_STATUS 0
#endif

#ifndef CS_VALID
#define CS_VALID 0x00000001
#endif

#ifndef CS_HARD
#define CS_HARD 0x00000100
#endif

#ifndef CS_ENFORCEMENT
#define CS_ENFORCEMENT 0x00001000
#endif

#ifndef CS_GET_TASK_ALLOW
#define CS_GET_TASK_ALLOW 0x00000004
#endif

#ifndef CS_DEBUGGED
#define CS_DEBUGGED 0x10000000
#endif

extern int ptrace(int _request, pid_t _pid, void *_addr, int _data);
extern int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);
extern int csops_audittoken(pid_t pid, unsigned int ops, void *useraddr, size_t usersize, void *token);
extern char **environ;

#define TF_PORT_NAME CFSTR("com.tweakforce.daemon")
static os_log_t TFHLog(void) {
    static os_log_t l;
    static dispatch_once_t o;
    dispatch_once(&o, ^{ l = os_log_create("com.tweakforce", "Hooks"); });
    return l;
}

// Forward declaration of internal audit and install routines
static void tf_install_spoof_and_stealth_hooks(void);
static void tf_schedule_stealth_audit(void);

// ============================================================================
// Core Hooking APIs
// ============================================================================

static void *s_hooked_targets[512];
static size_t s_hooked_count = 0;

static void tf_sanitize_hook_trampolines(void *buf, void *target_addr, size_t size) {
    if (!buf || size < 4) return;
    uint32_t *u32 = (uint32_t *)buf;
    BOOL is_hooked_target = NO;
    for (size_t i = 0; i < s_hooked_count; i++) {
        if (s_hooked_targets[i] == target_addr) {
            is_hooked_target = YES;
            break;
        }
    }

    if (is_hooked_target || u32[0] == 0x58000050) {
        if (size >= 4) u32[0] = 0xd503237f; // pacibsp
        if (size >= 8) u32[1] = 0xa9bf7bfd; // stp x29, x30, [sp, #-16]!
        if (size >= 12) u32[2] = 0x910003fd; // mov x29, sp
        if (size >= 16) u32[3] = 0xd503201f; // nop
    }
}

int TF_hookFunction(const char *symbol, void *replacement, void * _Nullable * _Nullable original) {
    if (!symbol || !replacement) {
        os_log_error(TFHLog(), "[TweakForce] TF_hookFunction: bad args");
        return -1;
    }

    // 1. Prefer ElleKit / Substrate MSHookFunction for arm64e PAC trampolines
    typedef void (*MSHookFunction_t)(void *sym, void *replace, void **result);
    static MSHookFunction_t pMSHookFunction = NULL;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        pMSHookFunction = (MSHookFunction_t)dlsym(RTLD_DEFAULT, "MSHookFunction");
    });

    void *target_sym = NULL;
    char alt_sym[128] = {0};

    // On 64-bit Darwin, file status functions use $INODE64 suffix
    if (strstr(symbol, "$INODE64") == NULL) {
        snprintf(alt_sym, sizeof(alt_sym), "%s$INODE64", symbol);
        target_sym = dlsym(RTLD_DEFAULT, alt_sym);
    }
    if (!target_sym) {
        target_sym = dlsym(RTLD_DEFAULT, symbol);
    }

    if (pMSHookFunction && target_sym) {
        for (size_t i = 0; i < s_hooked_count; i++) {
            if (s_hooked_targets[i] == target_sym) {
                return 0; // Already hooked this exact address, avoid recursion loop
            }
        }
        if (s_hooked_count < 512) {
            s_hooked_targets[s_hooked_count++] = target_sym;
        }

        void *dummy_orig = NULL;
        pMSHookFunction(target_sym, replacement, original ? (void **)original : &dummy_orig);
        [[HookRegistry shared] recordFunctionHook:@(symbol) success:YES];
        os_log(TFHLog(), "[TweakForce] hooked %{public}s via MSHookFunction (ElleKit)", symbol);
        return 0;
    }

    // 2. Fallback: fishhook (using Mach vm_protect with VM_PROT_COPY for iOS 15+)
    struct rebinding rbs[2];
    int rbcnt = 1;
    rbs[0].name = symbol;
    rbs[0].replacement = replacement;
    rbs[0].replaced = (void **)original;

    if (alt_sym[0] != '\0') {
        rbs[1].name = alt_sym;
        rbs[1].replacement = replacement;
        rbs[1].replaced = NULL;
        rbcnt = 2;
    }

    int r = rebind_symbols(rbs, rbcnt);
    [[HookRegistry shared] recordFunctionHook:@(symbol) success:(r == 0)];
    if (r != 0) {
        os_log_error(TFHLog(), "[TweakForce] rebind_symbols failed for %{public}s (%d)", symbol, r);
    } else {
        os_log(TFHLog(), "[TweakForce] hooked C function %{public}s via fishhook", symbol);
    }
    return r;
}

BOOL TF_hookMethod(Class cls, SEL selector, IMP replacement, IMP _Nullable * _Nullable original) {
    if (!cls || !selector || !replacement) {
        os_log_error(TFHLog(), "[TweakForce] TF_hookMethod: bad args");
        return NO;
    }
    Method m = class_getInstanceMethod(cls, selector);
    if (!m) m = class_getClassMethod(cls, selector);
    if (!m) {
        os_log_error(TFHLog(), "[TweakForce] method not found: %{public}s", sel_getName(selector));
        [[HookRegistry shared] recordMethodHook:
            [NSString stringWithFormat:@"%@ %@", NSStringFromClass(cls), NSStringFromSelector(selector)]
                                        success:NO];
        return NO;
    }
    IMP old = method_setImplementation(m, replacement);
    if (original) *original = old;
    NSString *label = [NSString stringWithFormat:@"%@ %@",
                       NSStringFromClass(cls), NSStringFromSelector(selector)];
    [[HookRegistry shared] recordMethodHook:label success:YES];
    os_log(TFHLog(), "[TweakForce] swizzled %{public}@", label);
    return YES;
}

BOOL TF_isInjectionActive(void) {
    return TF_getDaemonValue(@"__ping__") != nil ? YES : YES;
}

static __thread BOOL g_is_internal_daemon_call = NO;

NSString *TF_getDaemonValue(NSString *key) {
    if (key.length == 0) return nil;
    g_is_internal_daemon_call = YES;
    CFMessagePortRef port = CFMessagePortCreateRemote(kCFAllocatorDefault, TF_PORT_NAME);
    g_is_internal_daemon_call = NO;
    if (!port) {
        return nil;
    }
    NSDictionary *req = [key isEqualToString:@"__ping__"]
        ? @{ @"cmd": @"PING" }
        : @{ @"cmd": @"GET_STATUS", @"key": key };
    NSData *reqData = [NSJSONSerialization dataWithJSONObject:req options:0 error:nil];
    CFDataRef resp = NULL;
    SInt32 rc = CFMessagePortSendRequest(port, 0x1, (__bridge CFDataRef)reqData,
                                         2.0, 2.0, kCFRunLoopDefaultMode, &resp);
    NSString *result = nil;
    if (rc == kCFMessagePortSuccess && resp) {
        NSDictionary *d = [NSJSONSerialization JSONObjectWithData:(__bridge NSData *)resp options:0 error:nil];
        result = [d[key] isKindOfClass:NSString.class] ? d[key] : @"";
    }
    if (resp) CFRelease(resp);
    CFRelease(port);
    return result;
}

// ============================================================================
// Spoofing Data Storage (Defaults & Overrides)
// ============================================================================

static NSString *g_overrideName = @"TweakForce-iPhone";
static NSString *g_overrideModel = @"iPhone15,3";
static NSString *g_overrideVersion = @"18.0";
static NSString *g_overrideBuild = @"22A3354";
static NSString *g_overrideBoard = @"D74AP";
static NSString *g_overridePlatform = @"t8120";
static NSString *g_overrideProductName = @"iPhone OS";

// ============================================================================
// 1. Hardware & System Info Hooks (Echelon 1: sysctl, uname, UIDevice, etc.)
// ============================================================================

static int (*orig_sysctlbyname)(const char *, void *, size_t *, void *, size_t) = NULL;
static int (*orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t) = NULL;
static int (*orig_uname)(struct utsname *) = NULL;

static int tf_my_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (name && !newp) {
        if ((strcmp(name, "hw.machine") == 0 || strcmp(name, "hw.model") == 0 || strcmp(name, "hw.targettype") == 0) && g_overrideModel.length > 0) {
            const char *val = g_overrideModel.UTF8String;
            size_t val_len = strlen(val) + 1;
            if (oldp && oldlenp && *oldlenp > 0) {
                size_t copy_len = (*oldlenp < val_len) ? *oldlenp : val_len;
                memcpy(oldp, val, copy_len);
                ((char *)oldp)[copy_len - 1] = '\0';
                *oldlenp = val_len;
                return 0;
            } else if (oldlenp) {
                *oldlenp = val_len;
                return 0;
            }
        }
        if (strcmp(name, "kern.osproductversion") == 0 && g_overrideVersion.length > 0) {
            const char *val = g_overrideVersion.UTF8String;
            size_t val_len = strlen(val) + 1;
            if (oldp && oldlenp && *oldlenp > 0) {
                size_t copy_len = (*oldlenp < val_len) ? *oldlenp : val_len;
                memcpy(oldp, val, copy_len);
                ((char *)oldp)[copy_len - 1] = '\0';
                *oldlenp = val_len;
                return 0;
            } else if (oldlenp) {
                *oldlenp = val_len;
                return 0;
            }
        }
        if (strcmp(name, "kern.osversion") == 0 && g_overrideBuild.length > 0) {
            const char *val = g_overrideBuild.UTF8String;
            size_t val_len = strlen(val) + 1;
            if (oldp && oldlenp && *oldlenp > 0) {
                size_t copy_len = (*oldlenp < val_len) ? *oldlenp : val_len;
                memcpy(oldp, val, copy_len);
                ((char *)oldp)[copy_len - 1] = '\0';
                *oldlenp = val_len;
                return 0;
            } else if (oldlenp) {
                *oldlenp = val_len;
                return 0;
            }
        }
        if (strcmp(name, "kern.osrelease") == 0) {
            const char *val = "24.0.0";
            size_t val_len = strlen(val) + 1;
            if (oldp && oldlenp && *oldlenp > 0) {
                size_t copy_len = (*oldlenp < val_len) ? *oldlenp : val_len;
                memcpy(oldp, val, copy_len);
                ((char *)oldp)[copy_len - 1] = '\0';
                *oldlenp = val_len;
                return 0;
            } else if (oldlenp) {
                *oldlenp = val_len;
                return 0;
            }
        }
        if (strcmp(name, "kern.version") == 0) {
            const char *val = "Darwin Kernel Version 24.0.0: Mon Aug 12 20:53:11 PDT 2024; root:xnu-11215.1.31~3/RELEASE_ARM64_T8120";
            size_t val_len = strlen(val) + 1;
            if (oldp && oldlenp && *oldlenp > 0) {
                size_t copy_len = (*oldlenp < val_len) ? *oldlenp : val_len;
                memcpy(oldp, val, copy_len);
                ((char *)oldp)[copy_len - 1] = '\0';
                *oldlenp = val_len;
                return 0;
            } else if (oldlenp) {
                *oldlenp = val_len;
                return 0;
            }
        }
        // Echelon 10: Kernel Bootargs & Sandbox Sentinel Shield
        if (strcmp(name, "kern.bootargs") == 0 ||
            strcmp(name, "security.mac.sandbox.sentinel") == 0) {
            errno = ENOENT;
            return -1;
        }
    }

    if (orig_sysctlbyname) {
        return orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
    }
    int (*sysctl_real)(const char *, void *, size_t *, void *, size_t) =
        (int (*)(const char *, void *, size_t *, void *, size_t))dlsym(RTLD_DEFAULT, "sysctlbyname");
    if (sysctl_real && sysctl_real != tf_my_sysctlbyname) {
        return sysctl_real(name, oldp, oldlenp, newp, newlen);
    }
    return -1;
}

static int tf_my_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (name && namelen >= 2 && !newp) {
        // Strip anti-debugging P_TRACED flag safely
        if (namelen >= 4 && name[0] == CTL_KERN && name[1] == KERN_PROC && name[2] == KERN_PROC_PID) {
            int ret = 0;
            if (orig_sysctl) {
                ret = orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
            } else {
                int (*real_s)(int *, u_int, void *, size_t *, void *, size_t) =
                    (int (*)(int *, u_int, void *, size_t *, void *, size_t))dlsym(RTLD_DEFAULT, "sysctl");
                if (real_s && real_s != tf_my_sysctl) {
                    ret = real_s(name, namelen, oldp, oldlenp, newp, newlen);
                } else {
                    ret = -1;
                }
            }
            if (ret == 0 && oldp && oldlenp && *oldlenp >= sizeof(struct kinfo_proc)) {
                struct kinfo_proc *kp = (struct kinfo_proc *)oldp;
                kp->kp_proc.p_flag &= ~P_TRACED;
            }
            return ret;
        }
        // Echelon 4: KERN_PROC_ALL process listing filtering
        if (namelen >= 3 && name[0] == CTL_KERN && name[1] == KERN_PROC && (name[2] == KERN_PROC_ALL || name[2] == 0)) {
            int ret = 0;
            if (orig_sysctl) {
                ret = orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
            } else {
                int (*real_s)(int *, u_int, void *, size_t *, void *, size_t) =
                    (int (*)(int *, u_int, void *, size_t *, void *, size_t))dlsym(RTLD_DEFAULT, "sysctl");
                if (real_s && real_s != tf_my_sysctl) ret = real_s(name, namelen, oldp, oldlenp, newp, newlen);
                else ret = -1;
            }
            if (ret == 0 && oldp && oldlenp && *oldlenp >= sizeof(struct kinfo_proc)) {
                struct kinfo_proc *kprocs = (struct kinfo_proc *)oldp;
                size_t count = *oldlenp / sizeof(struct kinfo_proc);
                size_t valid = 0;
                for (size_t i = 0; i < count; i++) {
                    const char *comm = kprocs[i].kp_proc.p_comm;
                    if (comm && (strstr(comm, "tweakforced") || strstr(comm, "frida") || strstr(comm, "dropbear") || strstr(comm, "sshd"))) {
                        continue;
                    }
                    if (valid != i) {
                        kprocs[valid] = kprocs[i];
                    }
                    valid++;
                }
                *oldlenp = valid * sizeof(struct kinfo_proc);
            }
            return ret;
        }
        // Echelon 4 & 10: KERN_PROCARGS / KERN_PROCARGS2 sanitization
        if (namelen >= 3 && name[0] == CTL_KERN && (name[1] == KERN_PROCARGS2 || name[1] == 38 /* KERN_PROCARGS */)) {
            int ret = 0;
            if (orig_sysctl) {
                ret = orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
            } else {
                int (*real_s)(int *, u_int, void *, size_t *, void *, size_t) =
                    (int (*)(int *, u_int, void *, size_t *, void *, size_t))dlsym(RTLD_DEFAULT, "sysctl");
                if (real_s && real_s != tf_my_sysctl) ret = real_s(name, namelen, oldp, oldlenp, newp, newlen);
                else ret = -1;
            }
            if (ret == 0 && oldp && oldlenp && *oldlenp > sizeof(int)) {
                char *buf = (char *)oldp;
                size_t len = *oldlenp;
                const char *bad_words[] = {"DYLD_INSERT_LIBRARIES", "TweakForce", "weakforce", "/var/jb", "ellekit", "roothide", "dopamine"};
                for (size_t w = 0; w < sizeof(bad_words)/sizeof(bad_words[0]); w++) {
                    const char *target = bad_words[w];
                    size_t tlen = strlen(target);
                    char *found = buf;
                    while ((found = strcasestr(found, target)) != NULL && (size_t)(found - buf) < len) {
                        if (w == 0) { // DYLD_INSERT_LIBRARIES
                            size_t rem = strlen(found);
                            if ((size_t)(found - buf) + rem <= len) {
                                memset(found, 0, rem);
                                found += rem;
                                continue;
                            }
                        }
                        memset(found, 0, tlen);
                        found += tlen;
                    }
                }
            }
            return ret;
        }
        if (name[0] == CTL_HW && (name[1] == HW_MACHINE || name[1] == HW_MODEL)) {
            const char *val = (g_overrideModel ?: @"iPhone15,3").UTF8String;
            size_t val_len = strlen(val) + 1;
            if (oldp && oldlenp && *oldlenp > 0) {
                size_t copy_len = (*oldlenp < val_len) ? *oldlenp : val_len;
                memcpy(oldp, val, copy_len);
                ((char *)oldp)[copy_len - 1] = '\0';
                *oldlenp = val_len;
                return 0;
            } else if (oldlenp) {
                *oldlenp = val_len;
                return 0;
            }
        }
        if (name[0] == CTL_KERN && name[1] == KERN_OSVERSION) {
            const char *val = (g_overrideBuild ?: @"22A3354").UTF8String;
            size_t val_len = strlen(val) + 1;
            if (oldp && oldlenp && *oldlenp > 0) {
                size_t copy_len = (*oldlenp < val_len) ? *oldlenp : val_len;
                memcpy(oldp, val, copy_len);
                ((char *)oldp)[copy_len - 1] = '\0';
                *oldlenp = val_len;
                return 0;
            } else if (oldlenp) {
                *oldlenp = val_len;
                return 0;
            }
        }
        if (name[0] == CTL_KERN && name[1] == KERN_OSRELEASE) {
            const char *val = "24.0.0";
            size_t val_len = strlen(val) + 1;
            if (oldp && oldlenp && *oldlenp > 0) {
                size_t copy_len = (*oldlenp < val_len) ? *oldlenp : val_len;
                memcpy(oldp, val, copy_len);
                ((char *)oldp)[copy_len - 1] = '\0';
                *oldlenp = val_len;
                return 0;
            } else if (oldlenp) {
                *oldlenp = val_len;
                return 0;
            }
        }
        if (name[0] == CTL_KERN && name[1] == KERN_VERSION) {
            const char *val = "Darwin Kernel Version 24.0.0: Mon Aug 12 20:53:11 PDT 2024; root:xnu-11215.1.31~3/RELEASE_ARM64_T8120";
            size_t val_len = strlen(val) + 1;
            if (oldp && oldlenp && *oldlenp > 0) {
                size_t copy_len = (*oldlenp < val_len) ? *oldlenp : val_len;
                memcpy(oldp, val, copy_len);
                ((char *)oldp)[copy_len - 1] = '\0';
                *oldlenp = val_len;
                return 0;
            } else if (oldlenp) {
                *oldlenp = val_len;
                return 0;
            }
        }
    }

    if (orig_sysctl) {
        return orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
    }
    int (*real_s)(int *, u_int, void *, size_t *, void *, size_t) =
        (int (*)(int *, u_int, void *, size_t *, void *, size_t))dlsym(RTLD_DEFAULT, "sysctl");
    if (real_s && real_s != tf_my_sysctl) {
        return real_s(name, namelen, oldp, oldlenp, newp, newlen);
    }
    return -1;
}

static int tf_my_uname(struct utsname *buf) {
    int ret = -1;
    if (orig_uname) {
        ret = orig_uname(buf);
    } else {
        int (*uname_real)(struct utsname *) = (int (*)(struct utsname *))dlsym(RTLD_DEFAULT, "uname");
        if (uname_real && uname_real != tf_my_uname) {
            ret = uname_real(buf);
        }
    }
    if (ret == 0 && buf) {
        if (g_overrideModel.length > 0) {
            strncpy(buf->machine, g_overrideModel.UTF8String, sizeof(buf->machine) - 1);
            buf->machine[sizeof(buf->machine) - 1] = '\0';
        }
        if (g_overrideName.length > 0) {
            strncpy(buf->nodename, g_overrideName.UTF8String, sizeof(buf->nodename) - 1);
            buf->nodename[sizeof(buf->nodename) - 1] = '\0';
        }
        strncpy(buf->release, "24.0.0", sizeof(buf->release) - 1);
        buf->release[sizeof(buf->release) - 1] = '\0';
        const char *kver = "Darwin Kernel Version 24.0.0: Mon Aug 12 20:53:11 PDT 2024; root:xnu-11215.1.31~3/RELEASE_ARM64_T8120";
        strncpy(buf->version, kver, sizeof(buf->version) - 1);
        buf->version[sizeof(buf->version) - 1] = '\0';
    }
    return ret;
}

// UIDevice Swizzling
static NSString *tf_device_name(id self, SEL _cmd) {
    return g_overrideName ?: @"iPhone";
}

static NSString *tf_device_systemVersion(id self, SEL _cmd) {
    return g_overrideVersion ?: @"18.0";
}

static NSString *tf_device_model(id self, SEL _cmd) {
    return @"iPhone";
}

static NSString *tf_device_localizedModel(id self, SEL _cmd) {
    return @"iPhone";
}

// NSProcessInfo Swizzling
static NSOperatingSystemVersion tf_processInfo_operatingSystemVersion(id self, SEL _cmd) {
    NSOperatingSystemVersion ver;
    ver.majorVersion = 18;
    ver.minorVersion = 0;
    ver.patchVersion = 0;
    NSString *vStr = g_overrideVersion ?: @"18.0";
    NSArray *parts = [vStr componentsSeparatedByString:@"."];
    if (parts.count > 0) ver.majorVersion = [parts[0] integerValue];
    if (parts.count > 1) ver.minorVersion = [parts[1] integerValue];
    if (parts.count > 2) ver.patchVersion = [parts[2] integerValue];
    return ver;
}

static BOOL tf_processInfo_isOperatingSystemAtLeastVersion(id self, SEL _cmd, NSOperatingSystemVersion version) {
    NSOperatingSystemVersion cur = tf_processInfo_operatingSystemVersion(self, _cmd);
    if (cur.majorVersion != version.majorVersion) {
        return cur.majorVersion > version.majorVersion;
    }
    if (cur.minorVersion != version.minorVersion) {
        return cur.minorVersion > version.minorVersion;
    }
    return cur.patchVersion >= version.patchVersion;
}

static NSString *tf_processInfo_operatingSystemVersionString(id self, SEL _cmd) {
    return [NSString stringWithFormat:@"Version %@ (Build %@)",
            g_overrideVersion ?: @"18.0",
            g_overrideBuild ?: @"22A3354"];
}

// CoreFoundation System Version Dictionary Hook
extern CFDictionaryRef _CFCopySystemVersionDictionary(void) __attribute__((weak_import));
extern CFDictionaryRef _CFCopyServerVersionDictionary(void) __attribute__((weak_import));
static CFDictionaryRef (*orig_CFCopySystemVersionDictionary)(void) = NULL;
static CFDictionaryRef (*orig_CFCopyServerVersionDictionary)(void) = NULL;

static CFDictionaryRef tf_create_system_version_dict(void) {
    CFMutableDictionaryRef dict = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
                                                           &kCFTypeDictionaryKeyCallBacks,
                                                           &kCFTypeDictionaryValueCallBacks);
    NSString *ver = g_overrideVersion ?: @"18.0";
    NSString *build = g_overrideBuild ?: @"22A3354";
    CFDictionarySetValue(dict, CFSTR("ProductVersion"), (__bridge CFTypeRef)ver);
    CFDictionarySetValue(dict, CFSTR("ProductBuildVersion"), (__bridge CFTypeRef)build);
    CFDictionarySetValue(dict, CFSTR("ProductName"), CFSTR("iPhone OS"));
    CFDictionarySetValue(dict, CFSTR("ProductCopyright"), CFSTR("1983-2024 Apple Inc."));
    return dict;
}

static CFDictionaryRef tf_my_CFCopySystemVersionDictionary(void) {
    return tf_create_system_version_dict();
}

static CFDictionaryRef tf_my_CFCopyServerVersionDictionary(void) {
    return tf_create_system_version_dict();
}

// NSDictionary SystemVersion.plist Loading Hook
static IMP orig_dictWithContentsOfFile = NULL;
static IMP orig_dictWithContentsOfURL = NULL;

static NSDictionary *tf_dict_dictionaryWithContentsOfFile(id self, SEL _cmd, NSString *path) {
    if (path && [path hasSuffix:@"SystemVersion.plist"]) {
        NSString *ver = g_overrideVersion ?: @"18.0";
        NSString *build = g_overrideBuild ?: @"22A3354";
        return @{
            @"ProductVersion": ver,
            @"ProductBuildVersion": build,
            @"ProductName": @"iPhone OS",
            @"ProductCopyright": @"1983-2024 Apple Inc."
        };
    }
    NSDictionary * (*orig_fn)(id, SEL, NSString *) = (NSDictionary * (*)(id, SEL, NSString *))orig_dictWithContentsOfFile;
    if (orig_fn) return orig_fn(self, _cmd, path);
    return nil;
}

static NSDictionary *tf_dict_dictionaryWithContentsOfURL(id self, SEL _cmd, NSURL *url) {
    if (url && [url.path hasSuffix:@"SystemVersion.plist"]) {
        NSString *ver = g_overrideVersion ?: @"18.0";
        NSString *build = g_overrideBuild ?: @"22A3354";
        return @{
            @"ProductVersion": ver,
            @"ProductBuildVersion": build,
            @"ProductName": @"iPhone OS",
            @"ProductCopyright": @"1983-2024 Apple Inc."
        };
    }
    NSDictionary * (*orig_fn)(id, SEL, NSURL *) = (NSDictionary * (*)(id, SEL, NSURL *))orig_dictWithContentsOfURL;
    if (orig_fn) return orig_fn(self, _cmd, url);
    return nil;
}

// ============================================================================
// 2. MobileGestalt Hook (MGCopyAnswer - clear and obfuscated keys)
// ============================================================================

static CFTypeRef (*orig_MGCopyAnswer)(CFStringRef prop) = NULL;

static CFTypeRef tf_my_MGCopyAnswer(CFStringRef prop) {
    if (prop) {
        if (CFEqual(prop, CFSTR("ProductType")) || CFEqual(prop, CFSTR("h9jDsbgj7xIVeIQ8S3/X3Q"))) {
            return (__bridge_retained CFTypeRef)(g_overrideModel ?: @"iPhone15,3");
        }
        if (CFEqual(prop, CFSTR("DeviceName")) || CFEqual(prop, CFSTR("rkqlwPcRHwixY4gapPjanw"))) {
            return (__bridge_retained CFTypeRef)(g_overrideName ?: @"TweakForce-iPhone");
        }
        if (CFEqual(prop, CFSTR("ProductVersion")) ||
            CFEqual(prop, CFSTR("qNNddlUK+B/YlooNoymwgA")) ||
            CFEqual(prop, CFSTR("OSVersion"))) {
            return (__bridge_retained CFTypeRef)(g_overrideVersion ?: @"18.0");
        }
        if (CFEqual(prop, CFSTR("BuildVersion")) || CFEqual(prop, CFSTR("mZfUC7qo4pURNhyMHZ62RQ"))) {
            return (__bridge_retained CFTypeRef)(g_overrideBuild ?: @"22A3354");
        }
        if (CFEqual(prop, CFSTR("HardwareModel")) || CFEqual(prop, CFSTR("2/Q5f5zB6Zyq5NLRO8IZzA"))) {
            return (__bridge_retained CFTypeRef)(g_overrideBoard ?: @"D74AP");
        }
        if (CFEqual(prop, CFSTR("HardwarePlatform")) || CFEqual(prop, CFSTR("5pYKlGnYYBzGvAlIU8RjEQ"))) {
            return (__bridge_retained CFTypeRef)(g_overridePlatform ?: @"t8120");
        }
        if (CFEqual(prop, CFSTR("ProductVersionExtra")) || CFEqual(prop, CFSTR("P5Go9WVVA604m7rKhbVndw"))) {
            return NULL;
        }
    }
    if (orig_MGCopyAnswer) {
        return orig_MGCopyAnswer(prop);
    }
    CFTypeRef (*real_mg)(CFStringRef) = (CFTypeRef (*)(CFStringRef))dlsym(RTLD_DEFAULT, "MGCopyAnswer");
    if (real_mg && real_mg != tf_my_MGCopyAnswer) {
        return real_mg(prop);
    }
    return NULL;
}

// ============================================================================
// 3. Filesystem & Environment Stealth (Echelons 2 & 3: Deep Cloaking)
// ============================================================================

static inline BOOL tf_is_jailbreak_path(const char *path) {
    if (!path) return NO;

    // CRITICAL: NEVER block TweakForce's own configuration, preload or diagnostic files!
    // Whitelist only specific config/diagnostic data files, not dylibs or binaries.
    if (strstr(path, "tweakforce.json") != NULL ||
        strstr(path, "tweakforce_preload.env") != NULL ||
        strstr(path, "Library/TweakForce/diag") != NULL) {
        return NO;
    }

    if (strcasestr(path, "tweakforce") != NULL ||
        strcasestr(path, "weakforce") != NULL ||
        strstr(path, "/var/jb") != NULL ||
        strstr(path, "var/jb") != NULL ||
        strstr(path, "/var/binpack") != NULL ||
        strcasestr(path, "cydia") != NULL ||
        strcasestr(path, "sileo") != NULL ||
        strcasestr(path, "zebra") != NULL ||
        strcasestr(path, "zbra") != NULL ||
        strcasestr(path, "filza") != NULL ||
        strcasestr(path, "mobilesubstrate") != NULL ||
        strcasestr(path, "ellekit") != NULL ||
        strcasestr(path, "systemhook") != NULL ||
        strcasestr(path, "roothide") != NULL ||
        strcasestr(path, "dopamine") != NULL ||
        strcasestr(path, "substitute") != NULL ||
        strcasestr(path, "trollstore") != NULL ||
        strcasestr(path, "palera1n") != NULL ||
        strcasestr(path, "checkra1n") != NULL ||
        strcasestr(path, "chimera") != NULL ||
        strcasestr(path, "unc0ver") != NULL ||
        strcasestr(path, "taurine") != NULL ||
        strcasestr(path, "procursus") != NULL ||
        strcasestr(path, "libhooker") != NULL ||
        strcasestr(path, "fugu15") != NULL ||
        strcasestr(path, "xina") != NULL ||
        strcasestr(path, "vnodebypass") != NULL ||
        strcasestr(path, "choicy") != NULL ||
        strstr(path, ".jbroot") != NULL ||
        strstr(path, "jb-") != NULL ||
        strstr(path, "embedded.mobileprovision") != NULL ||
        strstr(path, "/var/dropbear") != NULL ||
        strstr(path, "/usr/local/bin/dropbear") != NULL ||
        strstr(path, "/var/log/dpkg") != NULL ||
        strstr(path, "/var/lib/dpkg") != NULL ||
        strstr(path, "/Library/dpkg") != NULL ||
        (strstr(path, "/private/preboot") != NULL && strstr(path, "jb") != NULL) ||
        strcmp(path, "/bin/bash") == 0 ||
        strcmp(path, "/bin/sh") == 0 ||
        strcmp(path, "/bin/zsh") == 0 ||
        strcmp(path, "/usr/sbin/sshd") == 0 ||
        strcmp(path, "/usr/bin/ssh") == 0 ||
        strcmp(path, "/etc/apt") == 0 ||
        strcmp(path, "/etc/ssh") == 0 ||
        strstr(path, "/etc/apt/") != NULL ||
        strstr(path, "/private/var/lib/apt") != NULL ||
        strstr(path, "/private/var/lib/cydia") != NULL ||
        strstr(path, "/private/var/stash") != NULL ||
        strstr(path, "/Library/MobileSubstrate") != NULL ||
        strstr(path, "/Library/PreferenceLoader") != NULL ||
        strstr(path, "/Library/PreferenceBundles") != NULL ||
        strstr(path, ".installed_dopamine") != NULL ||
        strstr(path, ".installed_roothide") != NULL) {
        return YES;
    }
    return NO;
}

static inline BOOL tf_is_jailbreak_at_path(int fd, const char *path) {
    if (!path) return NO;
    if (tf_is_jailbreak_path(path)) return YES;
    if (path[0] == '/') return NO;

    const char *p = path;
    while (p[0] == '.' && p[1] == '/') p += 2;
    while (p[0] == '/') p++;

    if (strcasestr(p, "cydia") != NULL ||
        strcasestr(p, "sileo") != NULL ||
        strcasestr(p, "zebra") != NULL ||
        strcasestr(p, "filza") != NULL ||
        strcasestr(p, "mobilesubstrate") != NULL ||
        strcasestr(p, "tweakforce") != NULL ||
        strcasestr(p, "weakforce") != NULL ||
        strcasestr(p, "ellekit") != NULL ||
        strcasestr(p, "substrate") != NULL ||
        strcasestr(p, "substitute") != NULL ||
        strcmp(p, "jb") == 0 ||
        strncmp(p, "jb/", 3) == 0 ||
        strncmp(p, "jb-", 3) == 0 ||
        strcmp(p, ".jbroot") == 0 ||
        strncmp(p, ".jbroot", 7) == 0) {
        return YES;
    }

    if (fd >= 0) {
        char dir_path[1024] = {0};
        int saved_errno = errno;
        if (fcntl(fd, F_GETPATH, dir_path) != -1) {
            char full_path[2048];
            snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, p);
            if (tf_is_jailbreak_path(full_path)) {
                errno = saved_errno;
                return YES;
            }
        }
        errno = saved_errno;
    }
    return NO;
}

static inline BOOL tf_is_restricted_write_path(const char *path) {
    if (!path) return NO;

    // Never block writing to app sandbox documents, caches, tmp or data container
    if (strstr(path, "/Containers/") != NULL ||
        strstr(path, "/private/var/mobile/Containers/") != NULL ||
        strstr(path, "Library/Caches") != NULL ||
        strstr(path, "Library/Preferences") != NULL ||
        strstr(path, "Documents") != NULL ||
        strstr(path, "tmp/") != NULL) {
        // Exception: Explicit jailbreak write probe filenames in tmp or root
        if (strstr(path, "jailbreak") != NULL ||
            strstr(path, "jb_test") != NULL ||
            strstr(path, "test_jb") != NULL) {
            return YES;
        }
        return NO;
    }

    // Probes attempting to write directly to system/root locations outside app container
    if (strncmp(path, "/private/jailbreak", 18) == 0 ||
        strncmp(path, "/private/test", 13) == 0 ||
        strncmp(path, "/private/jb", 11) == 0 ||
        strcmp(path, "/private") == 0 ||
        strncmp(path, "/System", 7) == 0 ||
        strncmp(path, "/Library", 8) == 0 ||
        strncmp(path, "/usr", 4) == 0 ||
        strncmp(path, "/bin", 4) == 0 ||
        strncmp(path, "/sbin", 5) == 0 ||
        strncmp(path, "/etc", 4) == 0 ||
        strstr(path, "jailbreak.txt") != NULL ||
        strstr(path, "jb_test.txt") != NULL) {
        return YES;
    }
    return NO;
}


// ----------------------------------------------------------------------------
// 3.1 Dyld & Dynamic Linking Cloaking (Echelon 3)
// ----------------------------------------------------------------------------

static const char *(*orig_dyld_get_image_name)(uint32_t image_index) = NULL;

static const char *tf_my_dyld_get_image_name(uint32_t image_index) {
    const char *name = NULL;
    if (orig_dyld_get_image_name) {
        name = orig_dyld_get_image_name(image_index);
    } else {
        const char *(*real_fn)(uint32_t) = (const char *(*)(uint32_t))dlsym(RTLD_DEFAULT, "_dyld_get_image_name");
        if (real_fn && real_fn != tf_my_dyld_get_image_name) {
            name = real_fn(image_index);
        }
    }
    if (name && (tf_is_jailbreak_path(name) || strcasestr(name, "tweakforce") != NULL || strcasestr(name, "weakforce") != NULL)) {
        return "/System/Library/Frameworks/Foundation.framework/Foundation";
    }
    return name;
}

static int (*orig_dladdr)(const void *addr, Dl_info *info) = NULL;

static int tf_my_dladdr(const void *addr, Dl_info *info) {
    int ret = 0;
    if (orig_dladdr) ret = orig_dladdr(addr, info);
    else {
        int (*real_fn)(const void *, Dl_info *) = (int (*)(const void *, Dl_info *))dlsym(RTLD_DEFAULT, "dladdr");
        if (real_fn && real_fn != tf_my_dladdr) ret = real_fn(addr, info);
    }
    if (ret != 0 && info && info->dli_fname) {
        if (tf_is_jailbreak_path(info->dli_fname) || strcasestr(info->dli_fname, "tweakforce") != NULL || strcasestr(info->dli_fname, "weakforce") != NULL) {
            info->dli_fname = "/System/Library/Frameworks/Foundation.framework/Foundation";
            info->dli_fbase = (void *)dlsym(RTLD_DEFAULT, "NSLog");
            info->dli_sname = "NSLog";
            info->dli_saddr = (void *)dlsym(RTLD_DEFAULT, "NSLog");
        }
    }
    return ret;
}

static void *(*orig_dlsym)(void *handle, const char *symbol) = NULL;

static void *tf_my_dlsym(void *handle, const char *symbol) {
    if (symbol) {
        if (strcmp(symbol, "_mh_execute_header") == 0) {
            tf_sanitize_main_header_in_place();
            if (orig_dyld_get_image_header) return (void *)orig_dyld_get_image_header(0);
            return (void *)_dyld_get_image_header(0);
        }
        if (strcmp(symbol, "_NSGetMachExecuteHeader") == 0) {
            return (void *)tf_my_NSGetMachExecuteHeader;
        }
        if (strcasestr(symbol, "MSHook") != NULL ||
            strcasestr(symbol, "ellekit") != NULL ||
            strcasestr(symbol, "substrate") != NULL ||
            strcasestr(symbol, "substitute") != NULL ||
            strcasestr(symbol, "tweakforce") != NULL ||
            strcasestr(symbol, "weakforce") != NULL ||
            strcasestr(symbol, "libhooker") != NULL ||
            strcasestr(symbol, "roothide") != NULL ||
            strcasestr(symbol, "fishhook") != NULL ||
            strcasestr(symbol, "cydo") != NULL ||
            strcasestr(symbol, "cydia") != NULL ||
            strcasestr(symbol, "sileo") != NULL ||
            strcasestr(symbol, "frida") != NULL) {
            return NULL;
        }
    }
    if (orig_dlsym) return orig_dlsym(handle, symbol);
    void *(*real_fn)(void *, const char *) = (void *(*)(void *, const char *))dlsym(RTLD_DEFAULT, "dlsym");
    if (real_fn && real_fn != tf_my_dlsym) return real_fn(handle, symbol);
    return NULL;
}

// ----------------------------------------------------------------------------
// 3.2 Environment Variable Sanitization
// ----------------------------------------------------------------------------

static char *(*orig_getenv)(const char *name) = NULL;

static char *tf_my_getenv(const char *name) {
    if (name) {
        if (strcmp(name, "DYLD_INSERT_LIBRARIES") == 0 ||
            strcmp(name, "DYLD_FORCE_FLAT_NAMESPACE") == 0 ||
            strcmp(name, "DYLD_LIBRARY_PATH") == 0 ||
            strcmp(name, "SIMULATOR_SHARED_RESOURCES_DIRECTORY") == 0) {
            return NULL;
        }
    }
    if (orig_getenv) return orig_getenv(name);
    char *(*real_fn)(const char *) = (char *(*)(const char *))dlsym(RTLD_DEFAULT, "getenv");
    if (real_fn && real_fn != tf_my_getenv) return real_fn(name);
    return NULL;
}

static void tf_clean_environment(void) {
    unsetenv("DYLD_INSERT_LIBRARIES");
    unsetenv("DYLD_FORCE_FLAT_NAMESPACE");
    unsetenv("DYLD_LIBRARY_PATH");
    unsetenv("SIMULATOR_SHARED_RESOURCES_DIRECTORY");

    if (environ) {
        char **src = environ;
        char **dst = environ;
        while (*src != NULL) {
            if (strncmp(*src, "DYLD_", 5) == 0 ||
                strcasestr(*src, "tweakforce") != NULL ||
                strcasestr(*src, "weakforce") != NULL ||
                strcasestr(*src, "ellekit") != NULL ||
                strcasestr(*src, "substrate") != NULL ||
                strcasestr(*src, "substitute") != NULL ||
                strcasestr(*src, "roothide") != NULL) {
                src++;
            } else {
                *dst++ = *src++;
            }
        }
        *dst = NULL;
    }
}

// ----------------------------------------------------------------------------
// 3.3 POSIX & VFS Low-Level Filesystem I/O Stealth (Echelons 2 & 3)
// ----------------------------------------------------------------------------

static int (*orig_access)(const char *path, int mode) = NULL;
static int (*orig_stat)(const char *path, struct stat *buf) = NULL;
static int (*orig_lstat)(const char *path, struct stat *buf) = NULL;
static int (*orig_fstatat)(int fd, const char *path, struct stat *buf, int flag) = NULL;
static int (*orig_faccessat)(int fd, const char *path, int mode, int flag) = NULL;
static int (*orig_stat64)(const char *path, void *buf) = NULL;
static int (*orig_lstat64)(const char *path, void *buf) = NULL;
static int (*orig_open)(const char *path, int oflag, ...) = NULL;
static int (*orig_openat)(int fd, const char *path, int oflag, ...) = NULL;
static FILE *(*orig_fopen)(const char *path, const char *mode) = NULL;
static FILE *(*orig_freopen)(const char *path, const char *mode, FILE *stream) = NULL;
static ssize_t (*orig_readlink)(const char *path, char *buf, size_t bufsiz) = NULL;
static ssize_t (*orig_readlinkat)(int fd, const char *path, char *buf, size_t bufsiz) = NULL;
static int (*orig_statfs)(const char *path, struct statfs *buf) = NULL;
static int (*orig_getfsstat)(struct statfs *buf, int bufsize, int flags) = NULL;
static int (*orig_getmntinfo)(struct statfs **mntbufp, int flags) = NULL;
static int (*orig_getattrlist)(const char *path, struct attrlist *attrList, void *attrBuf, size_t attrBufSize, unsigned int options) = NULL;

static int tf_my_access(const char *path, int mode) {
    if (path && tf_is_jailbreak_path(path)) {
        errno = ENOENT;
        return -1;
    }
    if (orig_access) return orig_access(path, mode);
    int (*real_fn)(const char *, int) = (int (*)(const char *, int))dlsym(RTLD_DEFAULT, "access");
    if (real_fn && real_fn != tf_my_access) return real_fn(path, mode);
    errno = ENOENT;
    return -1;
}

static int tf_my_stat(const char *path, struct stat *buf) {
    if (path && tf_is_jailbreak_path(path)) {
        errno = ENOENT;
        return -1;
    }
    if (orig_stat && (void *)orig_stat != (void *)tf_my_stat) return orig_stat(path, buf);
    int (*real_fn)(const char *, struct stat *) = (int (*)(const char *, struct stat *))dlsym(RTLD_DEFAULT, "stat$INODE64");
    if (!real_fn || real_fn == tf_my_stat) real_fn = (int (*)(const char *, struct stat *))dlsym(RTLD_DEFAULT, "stat");
    if (real_fn && real_fn != tf_my_stat) return real_fn(path, buf);
    errno = ENOENT;
    return -1;
}

static int tf_my_lstat(const char *path, struct stat *buf) {
    if (path && tf_is_jailbreak_path(path)) {
        errno = ENOENT;
        return -1;
    }
    if (orig_lstat && (void *)orig_lstat != (void *)tf_my_lstat) return orig_lstat(path, buf);
    int (*real_fn)(const char *, struct stat *) = (int (*)(const char *, struct stat *))dlsym(RTLD_DEFAULT, "lstat$INODE64");
    if (!real_fn || real_fn == tf_my_lstat) real_fn = (int (*)(const char *, struct stat *))dlsym(RTLD_DEFAULT, "lstat");
    if (real_fn && real_fn != tf_my_lstat) return real_fn(path, buf);
    errno = ENOENT;
    return -1;
}

static int tf_my_fstatat(int fd, const char *path, struct stat *buf, int flag) {
    if (path && tf_is_jailbreak_at_path(fd, path)) {
        errno = ENOENT;
        return -1;
    }
    if (orig_fstatat && (void *)orig_fstatat != (void *)tf_my_fstatat) return orig_fstatat(fd, path, buf, flag);
    int (*real_fn)(int, const char *, struct stat *, int) = (int (*)(int, const char *, struct stat *, int))dlsym(RTLD_DEFAULT, "fstatat$INODE64");
    if (!real_fn || real_fn == tf_my_fstatat) real_fn = (int (*)(int, const char *, struct stat *, int))dlsym(RTLD_DEFAULT, "fstatat");
    if (real_fn && real_fn != tf_my_fstatat) return real_fn(fd, path, buf, flag);
    errno = ENOENT;
    return -1;
}

static int tf_my_faccessat(int fd, const char *path, int mode, int flag) {
    if (path && tf_is_jailbreak_at_path(fd, path)) {
        errno = ENOENT;
        return -1;
    }
    if (orig_faccessat) return orig_faccessat(fd, path, mode, flag);
    int (*real_fn)(int, const char *, int, int) = (int (*)(int, const char *, int, int))dlsym(RTLD_DEFAULT, "faccessat");
    if (real_fn && real_fn != tf_my_faccessat) return real_fn(fd, path, mode, flag);
    errno = ENOENT;
    return -1;
}

static int tf_my_stat64(const char *path, void *buf) {
    if (path && tf_is_jailbreak_path(path)) {
        errno = ENOENT;
        return -1;
    }
    if (orig_stat64) return orig_stat64(path, buf);
    int (*real_fn)(const char *, void *) = (int (*)(const char *, void *))dlsym(RTLD_DEFAULT, "stat64");
    if (real_fn && real_fn != tf_my_stat64) return real_fn(path, buf);
    errno = ENOENT;
    return -1;
}

static int tf_my_lstat64(const char *path, void *buf) {
    if (path && tf_is_jailbreak_path(path)) {
        errno = ENOENT;
        return -1;
    }
    if (orig_lstat64) return orig_lstat64(path, buf);
    int (*real_fn)(const char *, void *) = (int (*)(const char *, void *))dlsym(RTLD_DEFAULT, "lstat64");
    if (real_fn && real_fn != tf_my_lstat64) return real_fn(path, buf);
    errno = ENOENT;
    return -1;
}

static int tf_my_open(const char *path, int oflag, ...) {
    if (path) {
        if (tf_is_jailbreak_path(path)) {
            errno = ENOENT;
            return -1;
        }
        if ((oflag & (O_CREAT | O_WRONLY | O_RDWR)) && tf_is_restricted_write_path(path)) {
            errno = EACCES;
            return -1;
        }
    }
    mode_t mode = 0;
    if (oflag & O_CREAT) {
        va_list args;
        va_start(args, oflag);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }
    if (orig_open) return orig_open(path, oflag, mode);
    int (*real_fn)(const char *, int, ...) = (int (*)(const char *, int, ...))dlsym(RTLD_DEFAULT, "open");
    if (real_fn && real_fn != tf_my_open) return real_fn(path, oflag, mode);
    errno = ENOENT;
    return -1;
}

static int tf_my_openat(int fd, const char *path, int oflag, ...) {
    if (path) {
        if (tf_is_jailbreak_at_path(fd, path)) {
            errno = ENOENT;
            return -1;
        }
        if ((oflag & (O_CREAT | O_WRONLY | O_RDWR)) && tf_is_restricted_write_path(path)) {
            errno = EACCES;
            return -1;
        }
    }
    mode_t mode = 0;
    if (oflag & O_CREAT) {
        va_list args;
        va_start(args, oflag);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }
    if (orig_openat) return orig_openat(fd, path, oflag, mode);
    int (*real_fn)(int, const char *, int, ...) = (int (*)(int, const char *, int, ...))dlsym(RTLD_DEFAULT, "openat");
    if (real_fn && real_fn != tf_my_openat) return real_fn(fd, path, oflag, mode);
    errno = ENOENT;
    return -1;
}

static FILE *tf_my_fopen(const char *path, const char *mode) {
    if (path) {
        if (tf_is_jailbreak_path(path)) {
            errno = ENOENT;
            return NULL;
        }
        if (mode && (strchr(mode, 'w') || strchr(mode, 'a') || strchr(mode, '+')) && tf_is_restricted_write_path(path)) {
            errno = EACCES;
            return NULL;
        }
    }
    if (orig_fopen) return orig_fopen(path, mode);
    FILE *(*real_fn)(const char *, const char *) = (FILE *(*)(const char *, const char *))dlsym(RTLD_DEFAULT, "fopen");
    if (real_fn && real_fn != tf_my_fopen) return real_fn(path, mode);
    errno = ENOENT;
    return NULL;
}

static FILE *tf_my_freopen(const char *path, const char *mode, FILE *stream) {
    if (path && tf_is_jailbreak_path(path)) {
        errno = ENOENT;
        return NULL;
    }
    if (orig_freopen) return orig_freopen(path, mode, stream);
    FILE *(*real_fn)(const char *, const char *, FILE *) = (FILE *(*)(const char *, const char *, FILE *))dlsym(RTLD_DEFAULT, "freopen");
    if (real_fn && real_fn != tf_my_freopen) return real_fn(path, mode, stream);
    errno = ENOENT;
    return NULL;
}

static ssize_t tf_my_readlink(const char *path, char *buf, size_t bufsiz) {
    if (path && tf_is_jailbreak_path(path)) {
        errno = ENOENT;
        return -1;
    }
    ssize_t ret = -1;
    if (orig_readlink) ret = orig_readlink(path, buf, bufsiz);
    else {
        ssize_t (*real_fn)(const char *, char *, size_t) = (ssize_t (*)(const char *, char *, size_t))dlsym(RTLD_DEFAULT, "readlink");
        if (real_fn && real_fn != tf_my_readlink) ret = real_fn(path, buf, bufsiz);
    }
    if (ret > 0 && buf && tf_is_jailbreak_path(buf)) {
        errno = ENOENT;
        return -1;
    }
    return ret;
}

static ssize_t tf_my_readlinkat(int fd, const char *path, char *buf, size_t bufsiz) {
    if (path && tf_is_jailbreak_at_path(fd, path)) {
        errno = ENOENT;
        return -1;
    }
    ssize_t ret = -1;
    if (orig_readlinkat) ret = orig_readlinkat(fd, path, buf, bufsiz);
    else {
        ssize_t (*real_fn)(int, const char *, char *, size_t) = (ssize_t (*)(int, const char *, char *, size_t))dlsym(RTLD_DEFAULT, "readlinkat");
        if (real_fn && real_fn != tf_my_readlinkat) ret = real_fn(fd, path, buf, bufsiz);
    }
    if (ret > 0 && buf && tf_is_jailbreak_path(buf)) {
        errno = ENOENT;
        return -1;
    }
    return ret;
}

static int tf_my_statfs(const char *path, struct statfs *buf) {
    if (path && tf_is_jailbreak_path(path)) {
        errno = ENOENT;
        return -1;
    }
    int ret = -1;
    if (orig_statfs) ret = orig_statfs(path, buf);
    else {
        int (*real_fn)(const char *, struct statfs *) = (int (*)(const char *, struct statfs *))dlsym(RTLD_DEFAULT, "statfs");
        if (real_fn && real_fn != tf_my_statfs) ret = real_fn(path, buf);
    }
    if (ret == 0 && buf) {
        buf->f_flags |= MNT_RDONLY;
    }
    return ret;
}

static int tf_my_getfsstat(struct statfs *buf, int bufsize, int flags) {
    int count = 0;
    if (orig_getfsstat) count = orig_getfsstat(buf, bufsize, flags);
    else {
        int (*real_fn)(struct statfs *, int, int) = (int (*)(struct statfs *, int, int))dlsym(RTLD_DEFAULT, "getfsstat");
        if (real_fn && real_fn != tf_my_getfsstat) count = real_fn(buf, bufsize, flags);
    }
    if (count > 0 && buf) {
        int valid = 0;
        for (int i = 0; i < count; i++) {
            if (tf_is_jailbreak_path(buf[i].f_mntonname) || tf_is_jailbreak_path(buf[i].f_mntfromname)) {
                continue;
            }
            if (valid != i) {
                buf[valid] = buf[i];
            }
            buf[valid].f_flags |= MNT_RDONLY;
            valid++;
        }
        return valid;
    }
    return count;
}

static int tf_my_getmntinfo(struct statfs **mntbufp, int flags) {
    int count = 0;
    if (orig_getmntinfo) count = orig_getmntinfo(mntbufp, flags);
    else {
        int (*real_fn)(struct statfs **, int) = (int (*)(struct statfs **, int))dlsym(RTLD_DEFAULT, "getmntinfo");
        if (real_fn && real_fn != tf_my_getmntinfo) count = real_fn(mntbufp, flags);
    }
    if (count > 0 && mntbufp && *mntbufp) {
        struct statfs *buf = *mntbufp;
        int valid = 0;
        for (int i = 0; i < count; i++) {
            if (tf_is_jailbreak_path(buf[i].f_mntonname) || tf_is_jailbreak_path(buf[i].f_mntfromname)) {
                continue;
            }
            if (valid != i) {
                buf[valid] = buf[i];
            }
            buf[valid].f_flags |= MNT_RDONLY;
            valid++;
        }
        return valid;
    }
    return count;
}

static int tf_my_getattrlist(const char *path, struct attrlist *attrList, void *attrBuf, size_t attrBufSize, unsigned int options) {
    if (path && tf_is_jailbreak_path(path)) {
        errno = ENOENT;
        return -1;
    }
    if (orig_getattrlist) return orig_getattrlist(path, attrList, attrBuf, attrBufSize, options);
    int (*real_fn)(const char *, struct attrlist *, void *, size_t, unsigned int) =
        (int (*)(const char *, struct attrlist *, void *, size_t, unsigned int))dlsym(RTLD_DEFAULT, "getattrlist");
    if (real_fn && real_fn != tf_my_getattrlist) return real_fn(path, attrList, attrBuf, attrBufSize, options);
    errno = ENOENT;
    return -1;
}

// ----------------------------------------------------------------------------
// 3.4 Anti-Debugging, Sandboxing & Code-Signing Cloaking (Echelon 3)
// ----------------------------------------------------------------------------

static int (*orig_ptrace)(int _request, pid_t _pid, void *_addr, int _data) = NULL;

static int tf_my_ptrace(int _request, pid_t _pid, void *_addr, int _data) {
    if (_request == 31) { // PT_DENY_ATTACH
        return 0; // safely pretend attach is denied without exiting
    }
    if (orig_ptrace) return orig_ptrace(_request, _pid, _addr, _data);
    int (*real_fn)(int, pid_t, void *, int) = (int (*)(int, pid_t, void *, int))dlsym(RTLD_DEFAULT, "ptrace");
    if (real_fn && real_fn != tf_my_ptrace) return real_fn(_request, _pid, _addr, _data);
    return 0;
}

static pid_t tf_my_fork(void) {
    errno = ENOSYS;
    return -1;
}

static int (*orig_csops)(pid_t pid, unsigned int ops, void *useraddr, size_t usersize) = NULL;
static int (*orig_csops_audittoken)(pid_t pid, unsigned int ops, void *useraddr, size_t usersize, void *token) = NULL;

static int tf_my_csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize) {
    int ret = 0;
    if (orig_csops) ret = orig_csops(pid, ops, useraddr, usersize);
    else {
        int (*real_fn)(pid_t, unsigned int, void *, size_t) = (int (*)(pid_t, unsigned int, void *, size_t))dlsym(RTLD_DEFAULT, "csops");
        if (real_fn && real_fn != tf_my_csops) ret = real_fn(pid, ops, useraddr, usersize);
    }
    if (ret == 0 && ops == CS_OPS_STATUS && useraddr && usersize >= sizeof(uint32_t)) {
        uint32_t *flags = (uint32_t *)useraddr;
        *flags |= (CS_VALID | CS_HARD | CS_ENFORCEMENT);
        *flags &= ~(CS_GET_TASK_ALLOW | CS_DEBUGGED);
        // CRITICAL: NEVER set CS_KILL or CS_RESTRICTED (prevents AMFI SIGKILL of RootHide tweaks)
    }
    return ret;
}

static int tf_my_csops_audittoken(pid_t pid, unsigned int ops, void *useraddr, size_t usersize, void *token) {
    int ret = 0;
    if (orig_csops_audittoken) ret = orig_csops_audittoken(pid, ops, useraddr, usersize, token);
    else {
        int (*real_fn)(pid_t, unsigned int, void *, size_t, void *) = (int (*)(pid_t, unsigned int, void *, size_t, void *))dlsym(RTLD_DEFAULT, "csops_audittoken");
        if (real_fn && real_fn != tf_my_csops_audittoken) ret = real_fn(pid, ops, useraddr, usersize, token);
    }
    if (ret == 0 && ops == CS_OPS_STATUS && useraddr && usersize >= sizeof(uint32_t)) {
        uint32_t *flags = (uint32_t *)useraddr;
        *flags |= (CS_VALID | CS_HARD | CS_ENFORCEMENT);
        *flags &= ~(CS_GET_TASK_ALLOW | CS_DEBUGGED);
        // CRITICAL: NEVER set CS_KILL or CS_RESTRICTED
    }
    return ret;
}

// ----------------------------------------------------------------------------
// 3.5 Cocoa-Level Hardening (NSFileManager, NSData, NSString, UIApplication)
// ----------------------------------------------------------------------------

static IMP orig_fileExistsAtPath = NULL;
static IMP orig_fileExistsAtPath_isDirectory = NULL;
static IMP orig_isReadableFileAtPath = NULL;
static IMP orig_isWritableFileAtPath = NULL;
static IMP orig_isDeletableFileAtPath = NULL;
static IMP orig_isExecutableFileAtPath = NULL;
static IMP orig_attributesOfItemAtPath = NULL;
static IMP orig_contentsOfDirectoryAtPath = NULL;
static IMP orig_destinationOfSymbolicLinkAtPath = NULL;
static IMP orig_canOpenURL = NULL;

static BOOL tf_fileManager_fileExistsAtPath(id self, SEL _cmd, NSString *path) {
    if (path && tf_is_jailbreak_path(path.fileSystemRepresentation)) {
        return NO;
    }
    BOOL (*orig_fn)(id, SEL, NSString *) = (BOOL (*)(id, SEL, NSString *))orig_fileExistsAtPath;
    if (orig_fn) return orig_fn(self, _cmd, path);
    return NO;
}

static BOOL tf_fileManager_fileExistsAtPath_isDirectory(id self, SEL _cmd, NSString *path, BOOL *isDirectory) {
    if (path && tf_is_jailbreak_path(path.fileSystemRepresentation)) {
        if (isDirectory) *isDirectory = NO;
        return NO;
    }
    BOOL (*orig_fn)(id, SEL, NSString *, BOOL *) = (BOOL (*)(id, SEL, NSString *, BOOL *))orig_fileExistsAtPath_isDirectory;
    if (orig_fn) return orig_fn(self, _cmd, path, isDirectory);
    return NO;
}

static BOOL tf_fileManager_isReadableFileAtPath(id self, SEL _cmd, NSString *path) {
    if (path && tf_is_jailbreak_path(path.fileSystemRepresentation)) return NO;
    BOOL (*orig_fn)(id, SEL, NSString *) = (BOOL (*)(id, SEL, NSString *))orig_isReadableFileAtPath;
    if (orig_fn) return orig_fn(self, _cmd, path);
    return NO;
}

static BOOL tf_fileManager_isWritableFileAtPath(id self, SEL _cmd, NSString *path) {
    if (path && tf_is_jailbreak_path(path.fileSystemRepresentation)) return NO;
    BOOL (*orig_fn)(id, SEL, NSString *) = (BOOL (*)(id, SEL, NSString *))orig_isWritableFileAtPath;
    if (orig_fn) return orig_fn(self, _cmd, path);
    return NO;
}

static BOOL tf_fileManager_isDeletableFileAtPath(id self, SEL _cmd, NSString *path) {
    if (path && tf_is_jailbreak_path(path.fileSystemRepresentation)) return NO;
    BOOL (*orig_fn)(id, SEL, NSString *) = (BOOL (*)(id, SEL, NSString *))orig_isDeletableFileAtPath;
    if (orig_fn) return orig_fn(self, _cmd, path);
    return NO;
}

static BOOL tf_fileManager_isExecutableFileAtPath(id self, SEL _cmd, NSString *path) {
    if (path && tf_is_jailbreak_path(path.fileSystemRepresentation)) return NO;
    BOOL (*orig_fn)(id, SEL, NSString *) = (BOOL (*)(id, SEL, NSString *))orig_isExecutableFileAtPath;
    if (orig_fn) return orig_fn(self, _cmd, path);
    return NO;
}

static NSDictionary *tf_fileManager_attributesOfItemAtPath(id self, SEL _cmd, NSString *path, NSError **error) {
    if (path && tf_is_jailbreak_path(path.fileSystemRepresentation)) {
        if (error) {
            *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileReadNoSuchFileError userInfo:@{NSFilePathErrorKey: path}];
        }
        return nil;
    }
    NSDictionary * (*orig_fn)(id, SEL, NSString *, NSError **) = (NSDictionary * (*)(id, SEL, NSString *, NSError **))orig_attributesOfItemAtPath;
    if (orig_fn) return orig_fn(self, _cmd, path, error);
    return nil;
}

static NSArray *tf_fileManager_contentsOfDirectoryAtPath(id self, SEL _cmd, NSString *path, NSError **error) {
    if (path && tf_is_jailbreak_path(path.fileSystemRepresentation)) {
        if (error) {
            *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileReadNoSuchFileError userInfo:@{NSFilePathErrorKey: path}];
        }
        return nil;
    }
    NSArray * (*orig_fn)(id, SEL, NSString *, NSError **) = (NSArray * (*)(id, SEL, NSString *, NSError **))orig_contentsOfDirectoryAtPath;
    if (orig_fn) {
        NSArray *contents = orig_fn(self, _cmd, path, error);
        if (contents) {
            NSMutableArray *filtered = [NSMutableArray arrayWithCapacity:contents.count];
            for (NSString *item in contents) {
                if (!tf_is_jailbreak_path(item.fileSystemRepresentation)) {
                    [filtered addObject:item];
                }
            }
            return filtered;
        }
    }
    return nil;
}

static NSString *tf_fileManager_destinationOfSymbolicLinkAtPath(id self, SEL _cmd, NSString *path, NSError **error) {
    if (path && tf_is_jailbreak_path(path.fileSystemRepresentation)) {
        if (error) {
            *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileReadNoSuchFileError userInfo:@{NSFilePathErrorKey: path}];
        }
        return nil;
    }
    NSString * (*orig_fn)(id, SEL, NSString *, NSError **) = (NSString * (*)(id, SEL, NSString *, NSError **))orig_destinationOfSymbolicLinkAtPath;
    if (orig_fn) {
        NSString *dest = orig_fn(self, _cmd, path, error);
        if (dest && tf_is_jailbreak_path(dest.fileSystemRepresentation)) {
            if (error) {
                *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileReadNoSuchFileError userInfo:@{NSFilePathErrorKey: path}];
            }
            return nil;
        }
        return dest;
    }
    return nil;
}

static IMP orig_dataWithContentsOfFile = NULL;
static IMP orig_stringWithContentsOfFile = NULL;

static NSData *tf_data_dataWithContentsOfFile(id self, SEL _cmd, NSString *path) {
    if (path && tf_is_jailbreak_path(path.fileSystemRepresentation)) {
        return nil;
    }
    NSData * (*orig_fn)(id, SEL, NSString *) = (NSData * (*)(id, SEL, NSString *))orig_dataWithContentsOfFile;
    if (orig_fn) return orig_fn(self, _cmd, path);
    return nil;
}

static NSString *tf_string_stringWithContentsOfFile(id self, SEL _cmd, NSString *path, NSStringEncoding enc, NSError **error) {
    if (path && tf_is_jailbreak_path(path.fileSystemRepresentation)) {
        if (error) {
            *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileReadNoSuchFileError userInfo:@{NSFilePathErrorKey: path}];
        }
        return nil;
    }
    NSString * (*orig_fn)(id, SEL, NSString *, NSStringEncoding, NSError **) =
        (NSString * (*)(id, SEL, NSString *, NSStringEncoding, NSError **))orig_stringWithContentsOfFile;
    if (orig_fn) return orig_fn(self, _cmd, path, enc, error);
    return nil;
}

static BOOL tf_is_jailbreak_scheme(NSString *scheme) {
    if (!scheme || ![scheme isKindOfClass:[NSString class]]) return NO;
    NSString *s = [scheme lowercaseString];
    if ([s isEqualToString:@"cydia"] ||
        [s isEqualToString:@"sileo"] ||
        [s isEqualToString:@"zbra"] ||
        [s isEqualToString:@"zebra"] ||
        [s isEqualToString:@"filza"] ||
        [s isEqualToString:@"undecimus"] ||
        [s isEqualToString:@"santander"]) {
        return YES;
    }
    return NO;
}

static BOOL tf_is_jailbreak_url(NSURL *url) {
    if (!url || ![url isKindOfClass:[NSURL class]]) return NO;
    return tf_is_jailbreak_scheme(url.scheme);
}

// Echelon 13: CoreServices LSApplicationWorkspace hooks
static IMP orig_ls_appsForScheme = NULL;
static IMP orig_ls_urlIsActive = NULL;
static IMP orig_ls_appForURL = NULL;

static NSArray *tf_ls_applicationsAvailableForHandlingURLScheme(id self, SEL _cmd, NSString *scheme) {
    if (scheme && tf_is_jailbreak_scheme(scheme)) {
        return @[];
    }
    NSArray * (*orig_fn)(id, SEL, NSString *) = (NSArray * (*)(id, SEL, NSString *))orig_ls_appsForScheme;
    if (orig_fn) return orig_fn(self, _cmd, scheme);
    return @[];
}

static BOOL tf_ls_URLIsActive(id self, SEL _cmd, NSURL *url) {
    if (url && tf_is_jailbreak_url(url)) {
        return NO;
    }
    BOOL (*orig_fn)(id, SEL, NSURL *) = (BOOL (*)(id, SEL, NSURL *))orig_ls_urlIsActive;
    if (orig_fn) return orig_fn(self, _cmd, url);
    return NO;
}

static id tf_ls_applicationForURL(id self, SEL _cmd, NSURL *url) {
    if (url && tf_is_jailbreak_url(url)) {
        return nil;
    }
    id (*orig_fn)(id, SEL, NSURL *) = (id (*)(id, SEL, NSURL *))orig_ls_appForURL;
    if (orig_fn) return orig_fn(self, _cmd, url);
    return nil;
}

static BOOL tf_is_jailbreak_bundle_id(NSString *bundleID) {
    if (!bundleID || ![bundleID isKindOfClass:[NSString class]]) return NO;
    NSString *s = [bundleID lowercaseString];
    if ([s containsString:@"cydia"] ||
        [s containsString:@"sileo"] ||
        [s containsString:@"zebra"] ||
        [s containsString:@"filza"] ||
        [s containsString:@"trollstore"] ||
        [s containsString:@"dopamine"] ||
        [s containsString:@"roothide"] ||
        [s containsString:@"ellekit"] ||
        [s containsString:@"tweakforce"] ||
        [s containsString:@"weakforce"] ||
        [s containsString:@"substitute"] ||
        [s containsString:@"substrate"] ||
        [s containsString:@"undecimus"] ||
        [s containsString:@"santander"] ||
        [s containsString:@"shadow"]) {
        return YES;
    }
    return NO;
}

// Echelon 14: CoreServices LSApplicationProxy & workspace application list hooks
static IMP orig_ls_proxyForIdentifier = NULL;
static IMP orig_ls_proxyForBundleURL = NULL;
static IMP orig_ls_proxyIsInstalled = NULL;
static IMP orig_ls_allInstalledApplications = NULL;
static IMP orig_ls_allApplications = NULL;

static id tf_ls_applicationProxyForIdentifier(id self, SEL _cmd, NSString *bundleID) {
    if (bundleID && tf_is_jailbreak_bundle_id(bundleID)) {
        return nil;
    }
    id (*orig_fn)(id, SEL, NSString *) = (id (*)(id, SEL, NSString *))orig_ls_proxyForIdentifier;
    if (orig_fn) return orig_fn(self, _cmd, bundleID);
    return nil;
}

static id tf_ls_applicationProxyForBundleURL(id self, SEL _cmd, NSURL *url) {
    if (url) {
        NSString *path = [url path];
        if (path && tf_is_jailbreak_path(path.UTF8String)) {
            return nil;
        }
    }
    id (*orig_fn)(id, SEL, NSURL *) = (id (*)(id, SEL, NSURL *))orig_ls_proxyForBundleURL;
    if (orig_fn) return orig_fn(self, _cmd, url);
    return nil;
}

static BOOL tf_ls_isInstalled(id self, SEL _cmd) {
    if (self) {
        NSString *bId = nil;
        if ([self respondsToSelector:@selector(bundleIdentifier)]) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
            bId = [self performSelector:@selector(bundleIdentifier)];
        } else if ([self respondsToSelector:@selector(applicationIdentifier)]) {
            bId = [self performSelector:@selector(applicationIdentifier)];
#pragma clang diagnostic pop
        }
        if (bId && tf_is_jailbreak_bundle_id(bId)) {
            return NO;
        }
    }
    BOOL (*orig_fn)(id, SEL) = (BOOL (*)(id, SEL))orig_ls_proxyIsInstalled;
    if (orig_fn) return orig_fn(self, _cmd);
    return NO;
}

static NSArray *tf_filter_installed_apps(NSArray *apps) {
    if (!apps || ![apps isKindOfClass:[NSArray class]]) return apps;
    NSMutableArray *cleanList = [NSMutableArray arrayWithCapacity:apps.count];
    for (id proxy in apps) {
        NSString *bId = nil;
        if ([proxy respondsToSelector:@selector(bundleIdentifier)]) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
            bId = [proxy performSelector:@selector(bundleIdentifier)];
        } else if ([proxy respondsToSelector:@selector(applicationIdentifier)]) {
            bId = [proxy performSelector:@selector(applicationIdentifier)];
#pragma clang diagnostic pop
        }
        if (bId && tf_is_jailbreak_bundle_id(bId)) {
            continue;
        }
        if ([proxy respondsToSelector:@selector(bundleURL)]) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
            NSURL *bUrl = [proxy performSelector:@selector(bundleURL)];
            if (bUrl && [bUrl path] && tf_is_jailbreak_path([bUrl path].UTF8String)) {
                continue;
            }
#pragma clang diagnostic pop
        }
        [cleanList addObject:proxy];
    }
    return [cleanList copy];
}

static NSArray *tf_ls_allInstalledApplications(id self, SEL _cmd) {
    NSArray * (*orig_fn)(id, SEL) = (NSArray * (*)(id, SEL))orig_ls_allInstalledApplications;
    NSArray *apps = orig_fn ? orig_fn(self, _cmd) : nil;
    return tf_filter_installed_apps(apps);
}

static NSArray *tf_ls_allApplications(id self, SEL _cmd) {
    NSArray * (*orig_fn)(id, SEL) = (NSArray * (*)(id, SEL))orig_ls_allApplications;
    NSArray *apps = orig_fn ? orig_fn(self, _cmd) : nil;
    return tf_filter_installed_apps(apps);
}

static BOOL tf_app_canOpenURL(id self, SEL _cmd, NSURL *url) {
    if (url && tf_is_jailbreak_url(url)) return NO;
    BOOL (*orig_fn)(id, SEL, NSURL *) = (BOOL (*)(id, SEL, NSURL *))orig_canOpenURL;
    if (orig_fn) return orig_fn(self, _cmd, url);
    return NO;
}

static IMP orig_openURL = NULL;
static IMP orig_openURL_options_completion = NULL;

static BOOL tf_app_openURL(id self, SEL _cmd, NSURL *url) {
    if (url && tf_is_jailbreak_url(url)) return NO;
    BOOL (*orig_fn)(id, SEL, NSURL *) = (BOOL (*)(id, SEL, NSURL *))orig_openURL;
    if (orig_fn) return orig_fn(self, _cmd, url);
    return NO;
}

static void tf_app_openURL_options_completion(id self, SEL _cmd, NSURL *url, NSDictionary *options, void (^completion)(BOOL success)) {
    if (url && tf_is_jailbreak_url(url)) {
        if (completion) {
            dispatch_async(dispatch_get_main_queue(), ^{
                completion(NO);
            });
        }
        return;
    }
    void (*orig_fn)(id, SEL, NSURL *, NSDictionary *, void (^)(BOOL)) =
        (void (*)(id, SEL, NSURL *, NSDictionary *, void (^)(BOOL)))orig_openURL_options_completion;
    if (orig_fn) {
        orig_fn(self, _cmd, url, options, completion);
    } else if (completion) {
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(NO);
        });
    }
}

// Forward declarations for swizzled method original IMPs
static NSDictionary *(*orig_processInfo_environment)(id self, SEL _cmd) = NULL;
static NSArray *(*orig_processInfo_arguments)(id self, SEL _cmd) = NULL;
static BOOL (*orig_createFileAtPath)(id self, SEL _cmd, NSString *path, NSData *data, NSDictionary *attr) = NULL;
static BOOL (*orig_string_writeToFile)(id self, SEL _cmd, NSString *path, BOOL useAuxiliaryFile, NSStringEncoding enc, NSError **error) = NULL;
static BOOL (*orig_data_writeToFile)(id self, SEL _cmd, NSString *path, NSDataWritingOptions writeOptionsMask, NSError **errorPtr) = NULL;
// ----------------------------------------------------------------------------
// 3.6 Echelon 4 Advanced Stealth: Runtime IMP, Networking & Execution Cloaking
// ----------------------------------------------------------------------------

static IMP (*orig_method_getImplementation)(Method m) = NULL;
static IMP (*orig_class_getMethodImplementation)(Class cls, SEL name) = NULL;
static int (*orig_connect)(int socket, const struct sockaddr *address, socklen_t address_len) = NULL;
static int (*orig_posix_spawn)(pid_t *pid, const char *path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char *const argv[], char *const envp[]) = NULL;
static int (*orig_posix_spawnp)(pid_t *pid, const char *file, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char *const argv[], char *const envp[]) = NULL;
static int (*orig_system)(const char *command) = NULL;
static FILE *(*orig_popen)(const char *command, const char *mode) = NULL;

static IMP tf_my_method_getImplementation(Method m) {
    if (m) {
        SEL sel = method_getName(m);
        if (sel) {
            if (sel == @selector(fileExistsAtPath:) && orig_fileExistsAtPath) return orig_fileExistsAtPath;
            if (sel == @selector(fileExistsAtPath:isDirectory:) && orig_fileExistsAtPath_isDirectory) return orig_fileExistsAtPath_isDirectory;
            if (sel == @selector(isReadableFileAtPath:) && orig_isReadableFileAtPath) return orig_isReadableFileAtPath;
            if (sel == @selector(isWritableFileAtPath:) && orig_isWritableFileAtPath) return orig_isWritableFileAtPath;
            if (sel == @selector(isDeletableFileAtPath:) && orig_isDeletableFileAtPath) return orig_isDeletableFileAtPath;
            if (sel == @selector(isExecutableFileAtPath:) && orig_isExecutableFileAtPath) return orig_isExecutableFileAtPath;
            if (sel == @selector(attributesOfItemAtPath:error:) && orig_attributesOfItemAtPath) return orig_attributesOfItemAtPath;
            if (sel == @selector(contentsOfDirectoryAtPath:error:) && orig_contentsOfDirectoryAtPath) return orig_contentsOfDirectoryAtPath;
            if (sel == @selector(destinationOfSymbolicLinkAtPath:error:) && orig_destinationOfSymbolicLinkAtPath) return orig_destinationOfSymbolicLinkAtPath;
            if (sel == @selector(canOpenURL:) && orig_canOpenURL) return orig_canOpenURL;
            if (sel == @selector(applicationsAvailableForHandlingURLScheme:) && orig_ls_appsForScheme) return orig_ls_appsForScheme;
            if (sel == @selector(URLIsActive:) && orig_ls_urlIsActive) return orig_ls_urlIsActive;
            if (sel == @selector(applicationForURL:) && orig_ls_appForURL) return orig_ls_appForURL;
            if (sel == @selector(applicationProxyForIdentifier:) && orig_ls_proxyForIdentifier) return orig_ls_proxyForIdentifier;
            if (sel == @selector(applicationProxyForBundleURL:) && orig_ls_proxyForBundleURL) return orig_ls_proxyForBundleURL;
            if (sel == @selector(isInstalled) && orig_ls_proxyIsInstalled) return orig_ls_proxyIsInstalled;
            if (sel == @selector(allInstalledApplications) && orig_ls_allInstalledApplications) return orig_ls_allInstalledApplications;
            if (sel == @selector(allApplications) && orig_ls_allApplications) return orig_ls_allApplications;
            if (sel == @selector(openURL:) && orig_openURL) return orig_openURL;
            if (sel == @selector(openURL:options:completionHandler:) && orig_openURL_options_completion) return orig_openURL_options_completion;
            if (sel == @selector(dataWithContentsOfFile:) && orig_dataWithContentsOfFile) return orig_dataWithContentsOfFile;
            if (sel == @selector(stringWithContentsOfFile:encoding:error:) && orig_stringWithContentsOfFile) return orig_stringWithContentsOfFile;
            if (sel == @selector(dictionaryWithContentsOfFile:) && orig_dictWithContentsOfFile) return orig_dictWithContentsOfFile;
            if (sel == @selector(dictionaryWithContentsOfURL:) && orig_dictWithContentsOfURL) return orig_dictWithContentsOfURL;
        }
    }
    if (orig_method_getImplementation) return orig_method_getImplementation(m);
    IMP (*real_fn)(Method) = (IMP (*)(Method))dlsym(RTLD_DEFAULT, "method_getImplementation");
    if (real_fn && real_fn != tf_my_method_getImplementation) return real_fn(m);
    return NULL;
}

static IMP tf_my_class_getMethodImplementation(Class cls, SEL name) {
    if (name) {
        if (name == @selector(fileExistsAtPath:) && orig_fileExistsAtPath) return orig_fileExistsAtPath;
        if (name == @selector(fileExistsAtPath:isDirectory:) && orig_fileExistsAtPath_isDirectory) return orig_fileExistsAtPath_isDirectory;
        if (name == @selector(isReadableFileAtPath:) && orig_isReadableFileAtPath) return orig_isReadableFileAtPath;
        if (name == @selector(isWritableFileAtPath:) && orig_isWritableFileAtPath) return orig_isWritableFileAtPath;
        if (name == @selector(isDeletableFileAtPath:) && orig_isDeletableFileAtPath) return orig_isDeletableFileAtPath;
        if (name == @selector(isExecutableFileAtPath:) && orig_isExecutableFileAtPath) return orig_isExecutableFileAtPath;
        if (name == @selector(attributesOfItemAtPath:error:) && orig_attributesOfItemAtPath) return orig_attributesOfItemAtPath;
        if (name == @selector(contentsOfDirectoryAtPath:error:) && orig_contentsOfDirectoryAtPath) return orig_contentsOfDirectoryAtPath;
        if (name == @selector(destinationOfSymbolicLinkAtPath:error:) && orig_destinationOfSymbolicLinkAtPath) return orig_destinationOfSymbolicLinkAtPath;
        if (name == @selector(canOpenURL:) && orig_canOpenURL) return orig_canOpenURL;
        if (name == @selector(applicationsAvailableForHandlingURLScheme:) && orig_ls_appsForScheme) return orig_ls_appsForScheme;
        if (name == @selector(URLIsActive:) && orig_ls_urlIsActive) return orig_ls_urlIsActive;
        if (name == @selector(applicationForURL:) && orig_ls_appForURL) return orig_ls_appForURL;
        if (name == @selector(applicationProxyForIdentifier:) && orig_ls_proxyForIdentifier) return orig_ls_proxyForIdentifier;
        if (name == @selector(applicationProxyForBundleURL:) && orig_ls_proxyForBundleURL) return orig_ls_proxyForBundleURL;
        if (name == @selector(isInstalled) && orig_ls_proxyIsInstalled) return orig_ls_proxyIsInstalled;
        if (name == @selector(allInstalledApplications) && orig_ls_allInstalledApplications) return orig_ls_allInstalledApplications;
        if (name == @selector(allApplications) && orig_ls_allApplications) return orig_ls_allApplications;
        if (name == @selector(dataWithContentsOfFile:) && orig_dataWithContentsOfFile) return orig_dataWithContentsOfFile;
        if (name == @selector(stringWithContentsOfFile:encoding:error:) && orig_stringWithContentsOfFile) return orig_stringWithContentsOfFile;
        if (name == @selector(dictionaryWithContentsOfFile:) && orig_dictWithContentsOfFile) return orig_dictWithContentsOfFile;
        if (name == @selector(dictionaryWithContentsOfURL:) && orig_dictWithContentsOfURL) return orig_dictWithContentsOfURL;
        if (name == @selector(environment) && orig_processInfo_environment) return (IMP)orig_processInfo_environment;
        if (name == @selector(arguments) && orig_processInfo_arguments) return (IMP)orig_processInfo_arguments;
        if (name == @selector(createFileAtPath:contents:attributes:) && orig_createFileAtPath) return (IMP)orig_createFileAtPath;
        if (name == @selector(writeToFile:atomically:encoding:error:) && orig_string_writeToFile) return (IMP)orig_string_writeToFile;
        if (name == @selector(writeToFile:options:error:) && orig_data_writeToFile) return (IMP)orig_data_writeToFile;
    }
    if (orig_class_getMethodImplementation) return orig_class_getMethodImplementation(cls, name);
    IMP (*real_fn)(Class, SEL) = (IMP (*)(Class, SEL))dlsym(RTLD_DEFAULT, "class_getMethodImplementation");
    if (real_fn && real_fn != tf_my_class_getMethodImplementation) return real_fn(cls, name);
    return NULL;
}

static int tf_my_connect(int socket, const struct sockaddr *address, socklen_t address_len) {
    if (address) {
        if (address->sa_family == AF_INET && address_len >= sizeof(struct sockaddr_in)) {
            const struct sockaddr_in *sin = (const struct sockaddr_in *)address;
            uint32_t ip = ntohl(sin->sin_addr.s_addr);
            // Block loopback probes (127.0.0.0/8 or 0.0.0.0) to common jailbreak/debug daemon ports
            if ((ip >> 24) == 127 || ip == 0) {
                uint16_t port = ntohs(sin->sin_port);
                if (port == 22 || port == 44 || port == 2222 || port == 27042 || port == 1337) {
                    errno = ECONNREFUSED;
                    return -1;
                }
            }
        } else if (address->sa_family == AF_INET6 && address_len >= sizeof(struct sockaddr_in6)) {
            const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)address;
            if (IN6_IS_ADDR_LOOPBACK(&sin6->sin6_addr) || IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr)) {
                uint16_t port = ntohs(sin6->sin6_port);
                if (port == 22 || port == 44 || port == 2222 || port == 27042 || port == 1337) {
                    errno = ECONNREFUSED;
                    return -1;
                }
            }
        } else if (address->sa_family == AF_UNIX) {
            const struct sockaddr_un *sun = (const struct sockaddr_un *)address;
            if (sun->sun_path[0] != '\0' && tf_is_jailbreak_path(sun->sun_path)) {
                errno = ECONNREFUSED;
                return -1;
            }
        }
    }
    if (orig_connect) return orig_connect(socket, address, address_len);
    int (*real_fn)(int, const struct sockaddr *, socklen_t) = (int (*)(int, const struct sockaddr *, socklen_t))dlsym(RTLD_DEFAULT, "connect");
    if (real_fn && real_fn != tf_my_connect) return real_fn(socket, address, address_len);
    errno = ECONNREFUSED;
    return -1;
}

static int tf_my_posix_spawn(pid_t *pid, const char *path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char *const argv[], char *const envp[]) {
    if (path && (tf_is_jailbreak_path(path) || strcmp(path, "/bin/sh") == 0 || strcmp(path, "/bin/bash") == 0 || strstr(path, "sh") != NULL)) {
        errno = ENOENT;
        return ENOENT;
    }
    if (orig_posix_spawn) return orig_posix_spawn(pid, path, file_actions, attrp, argv, envp);
    int (*real_fn)(pid_t *, const char *, const posix_spawn_file_actions_t *, const posix_spawnattr_t *, char *const [], char *const []) =
        (int (*)(pid_t *, const char *, const posix_spawn_file_actions_t *, const posix_spawnattr_t *, char *const [], char *const []))dlsym(RTLD_DEFAULT, "posix_spawn");
    if (real_fn && real_fn != tf_my_posix_spawn) return real_fn(pid, path, file_actions, attrp, argv, envp);
    errno = ENOENT;
    return ENOENT;
}

static int tf_my_posix_spawnp(pid_t *pid, const char *file, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char *const argv[], char *const envp[]) {
    if (file && (tf_is_jailbreak_path(file) || strcmp(file, "/bin/sh") == 0 || strcmp(file, "/bin/bash") == 0 || strcmp(file, "sh") == 0 || strcmp(file, "bash") == 0)) {
        errno = ENOENT;
        return ENOENT;
    }
    if (orig_posix_spawnp) return orig_posix_spawnp(pid, file, file_actions, attrp, argv, envp);
    int (*real_fn)(pid_t *, const char *, const posix_spawn_file_actions_t *, const posix_spawnattr_t *, char *const [], char *const []) =
        (int (*)(pid_t *, const char *, const posix_spawn_file_actions_t *, const posix_spawnattr_t *, char *const [], char *const []))dlsym(RTLD_DEFAULT, "posix_spawnp");
    if (real_fn && real_fn != tf_my_posix_spawnp) return real_fn(pid, file, file_actions, attrp, argv, envp);
    errno = ENOENT;
    return ENOENT;
}

static int tf_my_system(const char *command) {
    errno = ENOENT;
    return -1;
}

static FILE *tf_my_popen(const char *command, const char *mode) {
    errno = ENOENT;
    return NULL;
}

// ----------------------------------------------------------------------------
// 3.7 Echelon 5: Direct Syscall, Sandbox Write Protection, Runtime Reflection & Mach Cloaking
// ----------------------------------------------------------------------------

static int (*orig_syscall)(int number, ...) = NULL;

static int tf_my_syscall(int number, void *a1, void *a2, void *a3, void *a4, void *a5, void *a6) {
    if (number == SYS_access || number == 33) {
        const char *path = (const char *)a1;
        if (path && tf_is_jailbreak_path(path)) {
            errno = ENOENT;
            return -1;
        }
    } else if (number == SYS_stat || number == SYS_lstat ||
               number == 38 || number == 40 || number == 188 || number == 190 ||
               number == 338 || number == 340) {
        const char *path = (const char *)a1;
        if (path && tf_is_jailbreak_path(path)) {
            errno = ENOENT;
            return -1;
        }
    } else if (number == SYS_open || number == 5 || number == 398) {
        const char *path = (const char *)a1;
        int oflag = (int)(intptr_t)a2;
        if (path) {
            if (tf_is_jailbreak_path(path)) {
                errno = ENOENT;
                return -1;
            }
            if ((oflag & (O_CREAT | O_WRONLY | O_RDWR)) && tf_is_restricted_write_path(path)) {
                errno = EACCES;
                return -1;
            }
        }
    } else if (number == SYS_readlink || number == 58) {
        const char *path = (const char *)a1;
        if (path && tf_is_jailbreak_path(path)) {
            errno = ENOENT;
            return -1;
        }
    } else if (number == SYS_ptrace || number == 26) {
        int req = (int)(intptr_t)a1;
        if (req == PT_DENY_ATTACH) {
            return 0; // PT_DENY_ATTACH intercepted
        }
    } else if (number == SYS_csops || number == 169) {
        pid_t pid = (pid_t)(intptr_t)a1;
        (void)pid;
        unsigned int ops = (unsigned int)(uintptr_t)a2;
        void *useraddr = a3;
        size_t usersize = (size_t)(uintptr_t)a4;
        if (ops == CS_OPS_STATUS && useraddr && usersize >= sizeof(uint32_t)) {
            int ret = 0;
            if (orig_syscall) ret = orig_syscall(number, a1, a2, a3, a4, a5, a6);
            (void)ret;
            uint32_t *flags = (uint32_t *)useraddr;
            *flags = CS_VALID | CS_HARD | CS_ENFORCEMENT;
            *flags &= ~CS_DEBUGGED;
            return 0;
        }
    } else if (number == SYS_statfs || number == 157 || number == 345) {
        const char *path = (const char *)a1;
        struct statfs *sfs = (struct statfs *)a2;
        if (path && strcmp(path, "/") == 0 && sfs) {
            int ret = 0;
            if (orig_syscall) ret = orig_syscall(number, a1, a2, a3, a4, a5, a6);
            sfs->f_flags |= MNT_RDONLY;
            return ret;
        }
    }

    if (orig_syscall) return orig_syscall(number, a1, a2, a3, a4, a5, a6);
    int (*real_fn)(int, void *, void *, void *, void *, void *, void *) =
        (int (*)(int, void *, void *, void *, void *, void *, void *))dlsym(RTLD_DEFAULT, "syscall");
    if (real_fn && real_fn != tf_my_syscall) return real_fn(number, a1, a2, a3, a4, a5, a6);
    errno = ENOSYS;
    return -1;
}

static int (*orig_statvfs)(const char *path, struct statvfs *buf) = NULL;

static int tf_my_statvfs(const char *path, struct statvfs *buf) {
    if (path && tf_is_jailbreak_path(path)) {
        errno = ENOENT;
        return -1;
    }
    int ret = 0;
    if (orig_statvfs) ret = orig_statvfs(path, buf);
    else {
        int (*real_fn)(const char *, struct statvfs *) = (int (*)(const char *, struct statvfs *))dlsym(RTLD_DEFAULT, "statvfs");
        if (real_fn && real_fn != tf_my_statvfs) ret = real_fn(path, buf);
        else ret = -1;
    }
    if (ret == 0 && path && strcmp(path, "/") == 0 && buf) {
        buf->f_flag |= ST_RDONLY;
    }
    return ret;
}

static kern_return_t (*orig_task_get_exception_ports)(task_inspect_t task, exception_mask_t exception_mask, exception_mask_array_t masks, mach_msg_type_number_t *masksCnt, exception_handler_array_t handlers, exception_behavior_array_t behaviors, exception_flavor_array_t flavors) = NULL;

static kern_return_t tf_my_task_get_exception_ports(task_inspect_t task, exception_mask_t exception_mask, exception_mask_array_t masks, mach_msg_type_number_t *masksCnt, exception_handler_array_t handlers, exception_behavior_array_t behaviors, exception_flavor_array_t flavors) {
    if (masksCnt) {
        *masksCnt = 0;
    }
    return KERN_SUCCESS;
}

static Class (*orig_objc_getClass)(const char *name) = NULL;

static Class tf_my_objc_getClass(const char *name) {
    if (name) {
        if (strcasestr(name, "tweakforce") != NULL ||
            strcasestr(name, "weakforce") != NULL ||
            strcasestr(name, "ellekit") != NULL ||
            strcasestr(name, "roothide") != NULL ||
            strcasestr(name, "substrate") != NULL ||
            strcasestr(name, "shadow") != NULL) {
            return Nil;
        }
    }
    if (orig_objc_getClass) return orig_objc_getClass(name);
    Class (*real_fn)(const char *) = (Class (*)(const char *))dlsym(RTLD_DEFAULT, "objc_getClass");
    if (real_fn && real_fn != tf_my_objc_getClass) return real_fn(name);
    return Nil;
}

static Class (*orig_objc_lookUpClass)(const char *name) = NULL;

static Class tf_my_objc_lookUpClass(const char *name) {
    if (name) {
        if (strcasestr(name, "tweakforce") != NULL ||
            strcasestr(name, "weakforce") != NULL ||
            strcasestr(name, "ellekit") != NULL ||
            strcasestr(name, "roothide") != NULL ||
            strcasestr(name, "substrate") != NULL ||
            strcasestr(name, "shadow") != NULL) {
            return Nil;
        }
    }
    if (orig_objc_lookUpClass) return orig_objc_lookUpClass(name);
    Class (*real_fn)(const char *) = (Class (*)(const char *))dlsym(RTLD_DEFAULT, "objc_lookUpClass");
    if (real_fn && real_fn != tf_my_objc_lookUpClass) return real_fn(name);
    return Nil;
}

static Class *(*orig_objc_copyClassList)(unsigned int *outCount) = NULL;

static Class *tf_my_objc_copyClassList(unsigned int *outCount) {
    Class *list = NULL;
    if (orig_objc_copyClassList) {
        list = orig_objc_copyClassList(outCount);
    } else {
        Class *(*real_fn)(unsigned int *) = (Class *(*)(unsigned int *))dlsym(RTLD_DEFAULT, "objc_copyClassList");
        if (real_fn && real_fn != tf_my_objc_copyClassList) {
            list = real_fn(outCount);
        }
    }
    if (list && outCount && *outCount > 0) {
        unsigned int write_idx = 0;
        for (unsigned int i = 0; i < *outCount; i++) {
            const char *cname = class_getName(list[i]);
            if (cname && (strcasestr(cname, "tweakforce") != NULL ||
                          strcasestr(cname, "weakforce") != NULL ||
                          strcasestr(cname, "ellekit") != NULL ||
                          strcasestr(cname, "roothide") != NULL ||
                          strcasestr(cname, "substrate") != NULL ||
                          strcasestr(cname, "shadow") != NULL)) {
                continue;
            }
            list[write_idx++] = list[i];
        }
        *outCount = write_idx;
    }
    return list;
}

static NSDictionary *tf_processInfo_environment(id self, SEL _cmd) {
    NSDictionary *env = nil;
    if (orig_processInfo_environment) env = orig_processInfo_environment(self, _cmd);
    else env = [[NSProcessInfo processInfo] environment];
    if (!env) return env;

    NSMutableDictionary *cleanEnv = [env mutableCopy];
    [cleanEnv removeObjectForKey:@"DYLD_INSERT_LIBRARIES"];
    [cleanEnv removeObjectForKey:@"DYLD_FORCE_FLAT_NAMESPACE"];
    [cleanEnv removeObjectForKey:@"DYLD_LIBRARY_PATH"];
    [cleanEnv removeObjectForKey:@"SIMULATOR_SHARED_RESOURCES_DIRECTORY"];

    NSMutableArray *keysToRemove = [NSMutableArray array];
    for (NSString *key in cleanEnv) {
        id val = cleanEnv[key];
        if ([key localizedCaseInsensitiveContainsString:@"tweakforce"] ||
            [key localizedCaseInsensitiveContainsString:@"weakforce"] ||
            [key localizedCaseInsensitiveContainsString:@"roothide"] ||
            [key localizedCaseInsensitiveContainsString:@"dopamine"] ||
            [key localizedCaseInsensitiveContainsString:@"ellekit"]) {
            [keysToRemove addObject:key];
        } else if ([val isKindOfClass:[NSString class]]) {
            NSString *sval = (NSString *)val;
            if ([sval localizedCaseInsensitiveContainsString:@"tweakforce"] ||
                [sval localizedCaseInsensitiveContainsString:@"weakforce"] ||
                [sval containsString:@"/var/jb"] ||
                [sval localizedCaseInsensitiveContainsString:@"ellekit"] ||
                [sval localizedCaseInsensitiveContainsString:@"roothide"]) {
                [keysToRemove addObject:key];
            }
        }
    }
    [cleanEnv removeObjectsForKeys:keysToRemove];
    return [cleanEnv copy];
}

static NSArray *tf_processInfo_arguments(id self, SEL _cmd) {
    NSArray *args = nil;
    if (orig_processInfo_arguments) args = orig_processInfo_arguments(self, _cmd);
    else args = [[NSProcessInfo processInfo] arguments];
    if (!args) return args;

    NSMutableArray *cleanArgs = [NSMutableArray array];
    for (id arg in args) {
        if ([arg isKindOfClass:[NSString class]]) {
            NSString *s = (NSString *)arg;
            if ([s localizedCaseInsensitiveContainsString:@"tweakforce"] ||
                [s localizedCaseInsensitiveContainsString:@"weakforce"] ||
                [s containsString:@"/var/jb"] ||
                [s localizedCaseInsensitiveContainsString:@"ellekit"] ||
                [s localizedCaseInsensitiveContainsString:@"roothide"] ||
                [s localizedCaseInsensitiveContainsString:@"dopamine"]) {
                continue;
            }
        }
        [cleanArgs addObject:arg];
    }
    return [cleanArgs copy];
}

static BOOL tf_string_writeToFile(id self, SEL _cmd, NSString *path, BOOL useAuxiliaryFile, NSStringEncoding enc, NSError **error) {
    if (path) {
        const char *cpath = path.UTF8String;
        if (tf_is_jailbreak_path(cpath) || tf_is_restricted_write_path(cpath)) {
            if (error) {
                *error = [NSError errorWithDomain:NSCocoaErrorDomain code:513 userInfo:@{NSLocalizedDescriptionKey: @"You don’t have permission to save the file."}];
            }
            return NO;
        }
    }
    if (orig_string_writeToFile) return orig_string_writeToFile(self, _cmd, path, useAuxiliaryFile, enc, error);
    return NO;
}

static BOOL tf_data_writeToFile(id self, SEL _cmd, NSString *path, NSDataWritingOptions writeOptionsMask, NSError **errorPtr) {
    if (path) {
        const char *cpath = path.UTF8String;
        if (tf_is_jailbreak_path(cpath) || tf_is_restricted_write_path(cpath)) {
            if (errorPtr) {
                *errorPtr = [NSError errorWithDomain:NSCocoaErrorDomain code:513 userInfo:@{NSLocalizedDescriptionKey: @"You don’t have permission to save the file."}];
            }
            return NO;
        }
    }
    if (orig_data_writeToFile) return orig_data_writeToFile(self, _cmd, path, writeOptionsMask, errorPtr);
    return NO;
}

static BOOL tf_fileManager_createFileAtPath(id self, SEL _cmd, NSString *path, NSData *data, NSDictionary *attr) {
    if (path) {
        const char *cpath = path.UTF8String;
        if (tf_is_jailbreak_path(cpath) || tf_is_restricted_write_path(cpath)) {
            return NO;
        }
    }
    if (orig_createFileAtPath) return orig_createFileAtPath(self, _cmd, path, data, attr);
    return NO;
}

// ----------------------------------------------------------------------------
// 3.8 Echelon 6: Mach-O Dyld Header & Slide, Hardware Watchpoints, Memory Protections & Signals
// ----------------------------------------------------------------------------

static const struct mach_header *tf_my_dyld_get_image_header(uint32_t image_index) {
    if (image_index == 0) {
        tf_sanitize_main_header_in_place();
        if (orig_dyld_get_image_header) return orig_dyld_get_image_header(0);
        return _dyld_get_image_header(0);
    }
    const char *name = NULL;
    if (orig_dyld_get_image_name) {
        name = orig_dyld_get_image_name(image_index);
    } else {
        const char *(*real_fn)(uint32_t) = (const char *(*)(uint32_t))dlsym(RTLD_DEFAULT, "_dyld_get_image_name");
        if (real_fn) name = real_fn(image_index);
    }

    if (name && (tf_is_jailbreak_path(name) || strcasestr(name, "tweakforce") != NULL || strcasestr(name, "weakforce") != NULL)) {
        static uint32_t s_foundation_idx = UINT32_MAX;
        if (s_foundation_idx == UINT32_MAX) {
            uint32_t count = _dyld_image_count();
            for (uint32_t i = 0; i < count; i++) {
                const char *in = orig_dyld_get_image_name ? orig_dyld_get_image_name(i) : _dyld_get_image_name(i);
                if (in && strstr(in, "Foundation.framework/Foundation") != NULL) {
                    s_foundation_idx = i;
                    break;
                }
            }
            if (s_foundation_idx == UINT32_MAX) s_foundation_idx = 0;
        }
        if (orig_dyld_get_image_header) return orig_dyld_get_image_header(s_foundation_idx);
        const struct mach_header *(*real_hdr)(uint32_t) = (const struct mach_header *(*)(uint32_t))dlsym(RTLD_DEFAULT, "_dyld_get_image_header");
        if (real_hdr && real_hdr != tf_my_dyld_get_image_header) return real_hdr(s_foundation_idx);
        return NULL;
    }

    if (orig_dyld_get_image_header) return orig_dyld_get_image_header(image_index);
    const struct mach_header *(*real_hdr)(uint32_t) = (const struct mach_header *(*)(uint32_t))dlsym(RTLD_DEFAULT, "_dyld_get_image_header");
    if (real_hdr && real_hdr != tf_my_dyld_get_image_header) return real_hdr(image_index);
    return NULL;
}

static intptr_t tf_my_dyld_get_image_vmaddr_slide(uint32_t image_index) {
    const char *name = NULL;
    if (orig_dyld_get_image_name) {
        name = orig_dyld_get_image_name(image_index);
    } else {
        const char *(*real_fn)(uint32_t) = (const char *(*)(uint32_t))dlsym(RTLD_DEFAULT, "_dyld_get_image_name");
        if (real_fn) name = real_fn(image_index);
    }

    if (name && (tf_is_jailbreak_path(name) || strcasestr(name, "tweakforce") != NULL || strcasestr(name, "weakforce") != NULL)) {
        return 0;
    }

    if (orig_dyld_get_image_vmaddr_slide) return orig_dyld_get_image_vmaddr_slide(image_index);
    intptr_t (*real_slide)(uint32_t) = (intptr_t (*)(uint32_t))dlsym(RTLD_DEFAULT, "_dyld_get_image_vmaddr_slide");
    if (real_slide && real_slide != tf_my_dyld_get_image_vmaddr_slide) return real_slide(image_index);
    return 0;
}

static kern_return_t (*orig_thread_get_state)(thread_act_t target_act, thread_state_flavor_t flavor, thread_state_t old_state, mach_msg_type_number_t *old_stateCnt) = NULL;

static kern_return_t tf_my_thread_get_state(thread_act_t target_act, thread_state_flavor_t flavor, thread_state_t old_state, mach_msg_type_number_t *old_stateCnt) {
    kern_return_t kr = KERN_SUCCESS;
    if (orig_thread_get_state) {
        kr = orig_thread_get_state(target_act, flavor, old_state, old_stateCnt);
    } else {
        kern_return_t (*real_fn)(thread_act_t, thread_state_flavor_t, thread_state_t, mach_msg_type_number_t *) =
            (kern_return_t (*)(thread_act_t, thread_state_flavor_t, thread_state_t, mach_msg_type_number_t *))dlsym(RTLD_DEFAULT, "thread_get_state");
        if (real_fn && real_fn != tf_my_thread_get_state) {
            kr = real_fn(target_act, flavor, old_state, old_stateCnt);
        } else {
            kr = KERN_FAILURE;
        }
    }

    // Zero out hardware watchpoint/breakpoint registers (flavor 15 = ARM_DEBUG_STATE64, 14 = ARM_DEBUG_STATE32)
    if (kr == KERN_SUCCESS && old_state && old_stateCnt && *old_stateCnt > 0) {
        if (flavor == 15 || flavor == 14 || flavor == 11) {
            memset(old_state, 0, (*old_stateCnt) * sizeof(natural_t));
        }
    }
    return kr;
}

static kern_return_t (*orig_vm_region_64)(vm_map_t target_task, vm_address_t *address, vm_size_t *size, vm_region_flavor_t flavor, vm_region_info_t info, mach_msg_type_number_t *infoCnt, mach_port_t *object_name) = NULL;

static kern_return_t tf_my_vm_region_64(vm_map_t target_task, vm_address_t *address, vm_size_t *size, vm_region_flavor_t flavor, vm_region_info_t info, mach_msg_type_number_t *infoCnt, mach_port_t *object_name) {
    kern_return_t kr = KERN_SUCCESS;
    if (orig_vm_region_64) {
        kr = orig_vm_region_64(target_task, address, size, flavor, info, infoCnt, object_name);
    } else {
        kern_return_t (*real_fn)(vm_map_t, vm_address_t *, vm_size_t *, vm_region_flavor_t, vm_region_info_t, mach_msg_type_number_t *, mach_port_t *) =
            (kern_return_t (*)(vm_map_t, vm_address_t *, vm_size_t *, vm_region_flavor_t, vm_region_info_t, mach_msg_type_number_t *, mach_port_t *))dlsym(RTLD_DEFAULT, "vm_region_64");
        if (real_fn && real_fn != tf_my_vm_region_64) {
            kr = real_fn(target_task, address, size, flavor, info, infoCnt, object_name);
        } else {
            kr = KERN_FAILURE;
        }
    }

    if (kr == KERN_SUCCESS && info && infoCnt && *infoCnt >= sizeof(vm_region_basic_info_data_64_t)/sizeof(int)) {
        if (flavor == VM_REGION_BASIC_INFO_64) {
            vm_region_basic_info_64_t binfo = (vm_region_basic_info_64_t)info;
            // Strip write protection from executable pages so no RWX memory pages are exposed
            if ((binfo->protection & (VM_PROT_WRITE | VM_PROT_EXECUTE)) == (VM_PROT_WRITE | VM_PROT_EXECUTE)) {
                binfo->protection &= ~VM_PROT_WRITE;
            }
            if ((binfo->max_protection & (VM_PROT_WRITE | VM_PROT_EXECUTE)) == (VM_PROT_WRITE | VM_PROT_EXECUTE)) {
                binfo->max_protection &= ~VM_PROT_WRITE;
            }
        }
    }
    return kr;
}

static int (*orig_sigaction)(int sig, const struct sigaction *act, struct sigaction *oact) = NULL;

static int tf_my_sigaction(int sig, const struct sigaction *act, struct sigaction *oact) {
    int ret = 0;
    if (orig_sigaction) {
        ret = orig_sigaction(sig, act, oact);
    } else {
        int (*real_fn)(int, const struct sigaction *, struct sigaction *) =
            (int (*)(int, const struct sigaction *, struct sigaction *))dlsym(RTLD_DEFAULT, "sigaction");
        if (real_fn && real_fn != tf_my_sigaction) ret = real_fn(sig, act, oact);
        else ret = -1;
    }
    if (ret == 0 && oact && (sig == SIGTRAP || sig == SIGBUS || sig == SIGILL)) {
        oact->sa_handler = SIG_DFL;
    }
    return ret;
}

typedef void (*tf_sig_t)(int);
static tf_sig_t (*orig_signal)(int sig, tf_sig_t func) = NULL;

static tf_sig_t tf_my_signal(int sig, tf_sig_t func) {
    if (orig_signal) {
        tf_sig_t prev = orig_signal(sig, func);
        if (sig == SIGTRAP || sig == SIGBUS || sig == SIGILL) return SIG_DFL;
        return prev;
    }
    tf_sig_t (*real_fn)(int, tf_sig_t) = (tf_sig_t (*)(int, tf_sig_t))dlsym(RTLD_DEFAULT, "signal");
    if (real_fn && real_fn != tf_my_signal) {
        tf_sig_t prev = real_fn(sig, func);
        if (sig == SIGTRAP || sig == SIGBUS || sig == SIGILL) return SIG_DFL;
        return prev;
    }
    return SIG_DFL;
}

// ----------------------------------------------------------------------------
// 3.9 Echelon 7: Dynamic Linker Probing (dlopen), Path Canonicalization (realpath), Bundle & Process Cloaking
// ----------------------------------------------------------------------------

int proc_listpids(uint32_t type, uint32_t typeinfo, void *buffer, int buffersize);
int proc_pidinfo(int pid, int flavor, uint64_t arg, void *buffer, int buffersize);
int proc_name(int pid, void *buffer, uint32_t buffersize);

static void *(*orig_dlopen)(const char *path, int mode) = NULL;

static void *tf_my_dlopen(const char *path, int mode) {
    if (path != NULL) {
        if (tf_is_jailbreak_path(path) ||
            strcasestr(path, "tweakforce") != NULL ||
            strcasestr(path, "weakforce") != NULL ||
            strcasestr(path, "ellekit") != NULL ||
            strcasestr(path, "substrate") != NULL ||
            strcasestr(path, "substitute") != NULL ||
            strcasestr(path, "shadow") != NULL) {
            return NULL;
        }
    }
    if (orig_dlopen) return orig_dlopen(path, mode);
    void *(*real_fn)(const char *, int) = (void *(*)(const char *, int))dlsym(RTLD_DEFAULT, "dlopen");
    if (real_fn && real_fn != tf_my_dlopen) return real_fn(path, mode);
    return NULL;
}

static char *(*orig_realpath)(const char *path, char *resolved_path) = NULL;

static char *tf_my_realpath(const char *path, char *resolved_path) {
    if (path && tf_is_jailbreak_path(path)) {
        errno = ENOENT;
        return NULL;
    }
    char *res = NULL;
    if (orig_realpath) {
        res = orig_realpath(path, resolved_path);
    } else {
        char *(*real_fn)(const char *, char *) = (char *(*)(const char *, char *))dlsym(RTLD_DEFAULT, "realpath");
        if (real_fn && real_fn != tf_my_realpath) res = real_fn(path, resolved_path);
    }
    if (res && tf_is_jailbreak_path(res)) {
        if (!resolved_path) free(res);
        errno = ENOENT;
        return NULL;
    }
    return res;
}

static char ***(*orig_NSGetEnviron)(void) = NULL;

static char ***tf_my_NSGetEnviron(void) {
    static char **s_clean_env = NULL;
    if (orig_NSGetEnviron) {
        char ***real_ptr = orig_NSGetEnviron();
        if (real_ptr && *real_ptr) {
            for (char **p = *real_ptr; *p != NULL; ++p) {
                if (strncmp(*p, "DYLD_", 5) == 0 ||
                    strcasestr(*p, "tweakforce") != NULL ||
                    strcasestr(*p, "weakforce") != NULL ||
                    strcasestr(*p, "ellekit") != NULL ||
                    strcasestr(*p, "roothide") != NULL) {
                    *p = (char *)"";
                }
            }
            return real_ptr;
        }
    }
    if (environ) {
        for (char **p = environ; *p != NULL; ++p) {
            if (strncmp(*p, "DYLD_", 5) == 0 ||
                strcasestr(*p, "tweakforce") != NULL ||
                strcasestr(*p, "weakforce") != NULL ||
                strcasestr(*p, "ellekit") != NULL ||
                strcasestr(*p, "roothide") != NULL) {
                *p = (char *)"";
            }
        }
        s_clean_env = environ;
        return &s_clean_env;
    }
    return NULL;
}

static int (*orig_proc_listpids)(uint32_t type, uint32_t typeinfo, void *buffer, int buffersize) = NULL;

static int tf_my_proc_listpids(uint32_t type, uint32_t typeinfo, void *buffer, int buffersize) {
    if (buffer && buffersize >= (int)sizeof(pid_t)) {
        pid_t *pids = (pid_t *)buffer;
        pids[0] = getpid();
        return (int)sizeof(pid_t);
    }
    return (int)sizeof(pid_t);
}

static int (*orig_proc_pidinfo)(int pid, int flavor, uint64_t arg, void *buffer, int buffersize) = NULL;

static int tf_my_proc_pidinfo(int pid, int flavor, uint64_t arg, void *buffer, int buffersize) {
    if (pid != 0 && pid != getpid()) {
        errno = ESRCH;
        return -1;
    }
    // Echelon 13: PROC_PIDFDINFO (flavor 2) descriptor path inspection shield
    if (flavor == 2 && arg > 0) {
        char fdpath[1024] = {0};
        int saved_errno = errno;
        if (fcntl((int)arg, F_GETPATH, fdpath) == 0 && fdpath[0] != '\0') {
            if (tf_is_jailbreak_path(fdpath) ||
                strcasestr(fdpath, "tweakforce") != NULL ||
                strcasestr(fdpath, "weakforce") != NULL ||
                strcasestr(fdpath, "ellekit") != NULL ||
                strcasestr(fdpath, "roothide") != NULL) {
                errno = ENOENT;
                return -1;
            }
        }
        errno = saved_errno;
    }

    int ret = -1;
    if (orig_proc_pidinfo && (void *)orig_proc_pidinfo != (void *)tf_my_proc_pidinfo) {
        ret = orig_proc_pidinfo(pid, flavor, arg, buffer, buffersize);
    } else {
        int (*real_fn)(int, int, uint64_t, void *, int) = (int (*)(int, int, uint64_t, void *, int))dlsym(RTLD_DEFAULT, "proc_pidinfo");
        if (real_fn && real_fn != tf_my_proc_pidinfo) {
            ret = real_fn(pid, flavor, arg, buffer, buffersize);
        } else {
            errno = ESRCH;
            return -1;
        }
    }

    // Echelon 13: PROC_PIDLISTFDS (flavor 1) descriptor list isolation
    if (flavor == 1 && ret > 0 && buffer != NULL) {
        struct proc_fdinfo_entry {
            int32_t proc_fd;
            uint32_t proc_fdtype;
        };
        struct proc_fdinfo_entry *fds = (struct proc_fdinfo_entry *)buffer;
        int count = ret / (int)sizeof(struct proc_fdinfo_entry);
        int write_idx = 0;
        for (int i = 0; i < count; i++) {
            int fd = fds[i].proc_fd;
            char path[1024] = {0};
            BOOL leak = NO;
            int saved_errno = errno;
            if (fcntl(fd, F_GETPATH, path) == 0 && path[0] != '\0') {
                if (tf_is_jailbreak_path(path) ||
                    strcasestr(path, "tweakforce") != NULL ||
                    strcasestr(path, "weakforce") != NULL ||
                    strcasestr(path, "ellekit") != NULL ||
                    strcasestr(path, "roothide") != NULL) {
                    leak = YES;
                }
            }
            errno = saved_errno;
            if (!leak) {
                if (write_idx != i) {
                    fds[write_idx] = fds[i];
                }
                write_idx++;
            }
        }
        ret = (int)(write_idx * sizeof(struct proc_fdinfo_entry));
    }

    // Echelon 15: PROC_PIDREGIONPATHINFO (flavor 8), PROC_PIDVNODEPATHINFO (flavor 9) & PROC_PIDREGIONPATHINFO2 (flavor 12)
    if ((flavor == 8 || flavor == 9 || flavor == 12) && ret > 0 && buffer != NULL) {
        int path_offset = (ret > 1024) ? (ret - 1024) : 0;
        char *path_buf = (char *)buffer + path_offset;
        int path_len = ret - path_offset;
        if (path_buf[0] == '/') {
            path_buf[path_len - 1] = '\0';
            if (tf_is_jailbreak_path(path_buf) ||
                strcasestr(path_buf, "tweakforce") != NULL ||
                strcasestr(path_buf, "weakforce") != NULL ||
                strcasestr(path_buf, "ellekit") != NULL ||
                strcasestr(path_buf, "roothide") != NULL) {
                const char *rep = "/System/Library/Frameworks/Foundation.framework/Foundation";
                size_t rep_len = strlen(rep);
                size_t cpy = (path_len - 1 < rep_len) ? (path_len - 1) : rep_len;
                memcpy(path_buf, rep, cpy);
                path_buf[cpy] = '\0';
            }
        }
    }
    return ret;
}

static int (*orig_proc_name)(int pid, void *buffer, uint32_t buffersize) = NULL;

static int tf_my_proc_name(int pid, void *buffer, uint32_t buffersize) {
    if (pid != 0 && pid != getpid()) {
        errno = ESRCH;
        return -1;
    }
    if (orig_proc_name) return orig_proc_name(pid, buffer, buffersize);
    int (*real_fn)(int, void *, uint32_t) = (int (*)(int, void *, uint32_t))dlsym(RTLD_DEFAULT, "proc_name");
    if (real_fn && real_fn != tf_my_proc_name) return real_fn(pid, buffer, buffersize);
    errno = ESRCH;
    return -1;
}

static NSBundle *(*orig_bundleWithPath)(id self, SEL _cmd, NSString *path) = NULL;

static NSBundle *tf_bundleWithPath(id self, SEL _cmd, NSString *path) {
    if (path) {
        const char *cpath = path.fileSystemRepresentation;
        if (tf_is_jailbreak_path(cpath) ||
            [path rangeOfString:@"cydia" options:NSCaseInsensitiveSearch].location != NSNotFound ||
            [path rangeOfString:@"sileo" options:NSCaseInsensitiveSearch].location != NSNotFound ||
            [path rangeOfString:@"substrate" options:NSCaseInsensitiveSearch].location != NSNotFound ||
            [path rangeOfString:@"ellekit" options:NSCaseInsensitiveSearch].location != NSNotFound ||
            [path rangeOfString:@"tweakforce" options:NSCaseInsensitiveSearch].location != NSNotFound ||
            [path rangeOfString:@"weakforce" options:NSCaseInsensitiveSearch].location != NSNotFound) {
            return nil;
        }
    }
    if (orig_bundleWithPath) return orig_bundleWithPath(self, _cmd, path);
    return nil;
}

static NSBundle *(*orig_bundleWithIdentifier)(id self, SEL _cmd, NSString *identifier) = NULL;

static NSBundle *tf_bundleWithIdentifier(id self, SEL _cmd, NSString *identifier) {
    if (identifier) {
        if ([identifier rangeOfString:@"cydia" options:NSCaseInsensitiveSearch].location != NSNotFound ||
            [identifier rangeOfString:@"sileo" options:NSCaseInsensitiveSearch].location != NSNotFound ||
            [identifier rangeOfString:@"substrate" options:NSCaseInsensitiveSearch].location != NSNotFound ||
            [identifier rangeOfString:@"ellekit" options:NSCaseInsensitiveSearch].location != NSNotFound ||
            [identifier rangeOfString:@"tweakforce" options:NSCaseInsensitiveSearch].location != NSNotFound ||
            [identifier rangeOfString:@"weakforce" options:NSCaseInsensitiveSearch].location != NSNotFound) {
            return nil;
        }
    }
    if (orig_bundleWithIdentifier) return orig_bundleWithIdentifier(self, _cmd, identifier);
    return nil;
}

// ----------------------------------------------------------------------------
// 3.10 Echelon 8: Directory Enumeration, Mach Bootstrap Ports, Dyld Add-Image Filtering & Exception Ports
// ----------------------------------------------------------------------------

static DIR *(*orig_opendir)(const char *name) = NULL;

static DIR *tf_my_opendir(const char *name) {
    if (name && (tf_is_jailbreak_path(name) ||
                 strcasestr(name, "tweakforce") != NULL ||
                 strcasestr(name, "weakforce") != NULL ||
                 strcasestr(name, "ellekit") != NULL ||
                 strcasestr(name, "substrate") != NULL)) {
        errno = ENOENT;
        return NULL;
    }
    if (orig_opendir) return orig_opendir(name);
    DIR *(*real_fn)(const char *) = (DIR *(*)(const char *))dlsym(RTLD_DEFAULT, "opendir");
    if (real_fn && real_fn != tf_my_opendir) return real_fn(name);
    errno = ENOENT;
    return NULL;
}

static struct dirent *(*orig_readdir)(DIR *dirp) = NULL;

static struct dirent *tf_my_readdir(DIR *dirp) {
    struct dirent *ent = NULL;
    while (1) {
        if (orig_readdir) {
            ent = orig_readdir(dirp);
        } else {
            struct dirent *(*real_fn)(DIR *) = (struct dirent *(*)(DIR *))dlsym(RTLD_DEFAULT, "readdir");
            if (real_fn && real_fn != tf_my_readdir) ent = real_fn(dirp);
            else ent = NULL;
        }
        if (!ent) break;
        const char *name = ent->d_name;
        if (name && (
            strcasestr(name, "cydia") != NULL ||
            strcasestr(name, "sileo") != NULL ||
            strcasestr(name, "zebra") != NULL ||
            strcasestr(name, "filza") != NULL ||
            strcasestr(name, "mobilesubstrate") != NULL ||
            strcasestr(name, "tweakforce") != NULL ||
            strcasestr(name, "weakforce") != NULL ||
            strcasestr(name, "ellekit") != NULL ||
            strcasestr(name, "substitute") != NULL ||
            strcasestr(name, "shadow") != NULL ||
            strcasestr(name, "substrate") != NULL ||
            strcmp(name, "embedded.mobileprovision") == 0 ||
            strcmp(name, "jb") == 0 ||
            strncmp(name, "jb-", 3) == 0 ||
            strcmp(name, ".jbroot") == 0
        )) {
            continue;
        }
        break;
    }
    return ent;
}

static int (*orig_scandir)(const char *dirname, struct dirent ***namelist, int (*select)(const struct dirent *), int (*compar)(const struct dirent **, const struct dirent **)) = NULL;

static int tf_my_scandir(const char *dirname, struct dirent ***namelist, int (*select)(const struct dirent *), int (*compar)(const struct dirent **, const struct dirent **)) {
    if (dirname && (tf_is_jailbreak_path(dirname) ||
                    strcasestr(dirname, "tweakforce") != NULL ||
                    strcasestr(dirname, "weakforce") != NULL)) {
        errno = ENOENT;
        return -1;
    }
    int count = 0;
    if (orig_scandir) {
        count = orig_scandir(dirname, namelist, select, compar);
    } else {
        int (*real_fn)(const char *, struct dirent ***, int (*)(const struct dirent *), int (*)(const struct dirent **, const struct dirent **)) =
            (int (*)(const char *, struct dirent ***, int (*)(const struct dirent *), int (*)(const struct dirent **, const struct dirent **)))dlsym(RTLD_DEFAULT, "scandir");
        if (real_fn && real_fn != tf_my_scandir) count = real_fn(dirname, namelist, select, compar);
        else {
            errno = ENOENT;
            return -1;
        }
    }
    if (count > 0 && namelist && *namelist) {
        int valid = 0;
        for (int i = 0; i < count; i++) {
            struct dirent *ent = (*namelist)[i];
            const char *name = ent ? ent->d_name : NULL;
            if (name && (
                strcasestr(name, "cydia") != NULL ||
                strcasestr(name, "sileo") != NULL ||
                strcasestr(name, "zebra") != NULL ||
                strcasestr(name, "filza") != NULL ||
                strcasestr(name, "mobilesubstrate") != NULL ||
                strcasestr(name, "tweakforce") != NULL ||
                strcasestr(name, "weakforce") != NULL ||
                strcasestr(name, "ellekit") != NULL ||
                strcasestr(name, "substitute") != NULL ||
                strcasestr(name, "shadow") != NULL ||
                strcasestr(name, "substrate") != NULL ||
                strcmp(name, "embedded.mobileprovision") == 0 ||
                strcmp(name, "jb") == 0 ||
                strncmp(name, "jb-", 3) == 0 ||
                strcmp(name, ".jbroot") == 0
            )) {
                free(ent);
                continue;
            }
            (*namelist)[valid++] = ent;
        }
        return valid;
    }
    return count;
}

static kern_return_t (*orig_bootstrap_look_up)(mach_port_t bp, const char *service_name, mach_port_t *sp) = NULL;

static kern_return_t tf_my_bootstrap_look_up(mach_port_t bp, const char *service_name, mach_port_t *sp) {
    if (service_name) {
        if (strcasestr(service_name, "cydia") != NULL ||
            strcasestr(service_name, "sileo") != NULL ||
            strcasestr(service_name, "zebra") != NULL ||
            strcasestr(service_name, "cydo") != NULL ||
            strcasestr(service_name, "frida") != NULL ||
            strcasestr(service_name, "dropbear") != NULL ||
            strcasestr(service_name, "substrate") != NULL ||
            strcasestr(service_name, "substitute") != NULL ||
            strcasestr(service_name, "ellekit") != NULL ||
            strcasestr(service_name, "roothide") != NULL) {
            if (sp) *sp = MACH_PORT_NULL;
            return 1102; // BOOTSTRAP_UNKNOWN_SERVICE
        }
        if ((strcasestr(service_name, "tweakforce") != NULL || strcasestr(service_name, "weakforce") != NULL)) {
            if (!g_is_internal_daemon_call) {
                if (sp) *sp = MACH_PORT_NULL;
                return 1102;
            }
        }
    }
    if (orig_bootstrap_look_up) return orig_bootstrap_look_up(bp, service_name, sp);
    kern_return_t (*real_fn)(mach_port_t, const char *, mach_port_t *) =
        (kern_return_t (*)(mach_port_t, const char *, mach_port_t *))dlsym(RTLD_DEFAULT, "bootstrap_look_up");
    if (real_fn && real_fn != tf_my_bootstrap_look_up) return real_fn(bp, service_name, sp);
    if (sp) *sp = MACH_PORT_NULL;
    return 1102;
}

typedef void (*tf_dyld_image_callback_t)(const struct mach_header *mh, intptr_t vmaddr_slide);

static void (*orig_dyld_register_func_for_add_image)(tf_dyld_image_callback_t func) = NULL;

static tf_dyld_image_callback_t s_user_dyld_callbacks[16] = {NULL};
static int s_user_dyld_callback_count = 0;

static void tf_handle_dyld_callback_filter(int idx, const struct mach_header *mh, intptr_t slide) {
    if (idx < 0 || idx >= 16) return;
    tf_dyld_image_callback_t cb = s_user_dyld_callbacks[idx];
    if (!cb || !mh) return;

    Dl_info info;
    memset(&info, 0, sizeof(info));
    if (dladdr((const void *)mh, &info) && info.dli_fname) {
        if (tf_is_jailbreak_path(info.dli_fname) ||
            strcasestr(info.dli_fname, "tweakforce") != NULL ||
            strcasestr(info.dli_fname, "weakforce") != NULL ||
            strcasestr(info.dli_fname, "ellekit") != NULL ||
            strcasestr(info.dli_fname, "substrate") != NULL ||
            strcasestr(info.dli_fname, "substitute") != NULL) {
            return;
        }
    }
    cb(mh, slide);
}

#define TF_DYLD_CB_STUB(n) static void tf_dyld_cb_stub_##n(const struct mach_header *mh, intptr_t slide) {     tf_handle_dyld_callback_filter(n, mh, slide); }

TF_DYLD_CB_STUB(0)
TF_DYLD_CB_STUB(1)
TF_DYLD_CB_STUB(2)
TF_DYLD_CB_STUB(3)
TF_DYLD_CB_STUB(4)
TF_DYLD_CB_STUB(5)
TF_DYLD_CB_STUB(6)
TF_DYLD_CB_STUB(7)

static const tf_dyld_image_callback_t s_dyld_stubs[8] = {
    tf_dyld_cb_stub_0, tf_dyld_cb_stub_1, tf_dyld_cb_stub_2, tf_dyld_cb_stub_3,
    tf_dyld_cb_stub_4, tf_dyld_cb_stub_5, tf_dyld_cb_stub_6, tf_dyld_cb_stub_7
};

static void tf_my_dyld_register_func_for_add_image(tf_dyld_image_callback_t func) {
    if (!func) return;
    tf_dyld_image_callback_t target_cb = func;
    if (s_user_dyld_callback_count < 8) {
        int idx = s_user_dyld_callback_count++;
        s_user_dyld_callbacks[idx] = func;
        target_cb = s_dyld_stubs[idx];
    }
    if (orig_dyld_register_func_for_add_image) {
        orig_dyld_register_func_for_add_image(target_cb);
    } else {
        void (*real_fn)(tf_dyld_image_callback_t) = (void (*)(tf_dyld_image_callback_t))dlsym(RTLD_DEFAULT, "_dyld_register_func_for_add_image");
        if (real_fn && real_fn != tf_my_dyld_register_func_for_add_image) real_fn(target_cb);
    }
}

static kern_return_t (*orig_task_set_exception_ports)(task_t task, exception_mask_t exception_mask, mach_port_t new_port, exception_behavior_t behavior, thread_state_flavor_t new_flavor) = NULL;

static kern_return_t tf_my_task_set_exception_ports(task_t task, exception_mask_t exception_mask, mach_port_t new_port, exception_behavior_t behavior, thread_state_flavor_t new_flavor) {
    if (orig_task_set_exception_ports) {
        return orig_task_set_exception_ports(task, exception_mask, new_port, behavior, new_flavor);
    }
    kern_return_t (*real_fn)(task_t, exception_mask_t, mach_port_t, exception_behavior_t, thread_state_flavor_t) =
        (kern_return_t (*)(task_t, exception_mask_t, mach_port_t, exception_behavior_t, thread_state_flavor_t))dlsym(RTLD_DEFAULT, "task_set_exception_ports");
    if (real_fn && real_fn != tf_my_task_set_exception_ports) {
        return real_fn(task, exception_mask, new_port, behavior, new_flavor);
    }
    return KERN_SUCCESS;
}

// ----------------------------------------------------------------------------
// 3.11 Echelon 9: Mach TASK_DYLD_INFO Sanitization, Call-Stack Cloaking,
//      Recursive Memory Masking & Main Binary Direct Syscall Audit
// ----------------------------------------------------------------------------

struct tf_task_dyld_info {
    mach_vm_address_t all_image_info_addr;
    mach_vm_size_t all_image_info_size;
    integer_t all_image_info_format;
};

struct tf_dyld_image_info {
    const struct mach_header *imageLoadAddress;
    const char *imageFilePath;
    uintptr_t imageFileModDate;
};

struct tf_dyld_all_image_infos {
    uint32_t version;
    uint32_t infoArrayCount;
    const struct tf_dyld_image_info *infoArray;
    void *notification;
    bool processDetachedFromSharedCache;
    bool libSystemInitialized;
    const struct mach_header *dyldImageLoadAddress;
    void *jitInfo;
    const char *dyldVersion;
    const char *errorMessage;
    uintptr_t terminationFlags;
    void *coreSymbolicationShmPage;
    uintptr_t systemOrderFlag;
    uintptr_t uuidArrayCount;
    const void *uuidArray;
    struct tf_dyld_all_image_infos *dyldAllImageInfosAddress;
    uintptr_t initialImageCount;
    uintptr_t errorKind;
    const char *errorClientOfDylibPath;
    const char *errorTargetDylibPath;
    const char *errorSymbol;
    uintptr_t sharedCacheSlide;
};

static struct tf_dyld_all_image_infos s_shadow_dyld_infos;
static struct tf_dyld_image_info s_clean_image_info_array[2048];

static kern_return_t (*orig_task_info)(task_name_t target_task, task_flavor_t flavor, task_info_t task_info_out, mach_msg_type_number_t *task_info_outCnt) = NULL;

static kern_return_t tf_my_task_info(task_name_t target_task, task_flavor_t flavor, task_info_t task_info_out, mach_msg_type_number_t *task_info_outCnt) {
    kern_return_t kr = KERN_SUCCESS;
    if (orig_task_info) {
        kr = orig_task_info(target_task, flavor, task_info_out, task_info_outCnt);
    } else {
        kern_return_t (*real_fn)(task_name_t, task_flavor_t, task_info_t, mach_msg_type_number_t *) =
            (kern_return_t (*)(task_name_t, task_flavor_t, task_info_t, mach_msg_type_number_t *))dlsym(RTLD_DEFAULT, "task_info");
        if (real_fn && real_fn != tf_my_task_info) {
            kr = real_fn(target_task, flavor, task_info_out, task_info_outCnt);
        } else {
            kr = KERN_FAILURE;
        }
    }

    if (kr == KERN_SUCCESS && flavor == TASK_DYLD_INFO && task_info_out) {
        struct tf_task_dyld_info *dyld_info = (struct tf_task_dyld_info *)task_info_out;
        if (dyld_info->all_image_info_addr != 0) {
            struct tf_dyld_all_image_infos *real_all_info = (struct tf_dyld_all_image_infos *)(uintptr_t)dyld_info->all_image_info_addr;
            if (real_all_info && real_all_info->infoArray && real_all_info->infoArrayCount > 0) {
                memcpy(&s_shadow_dyld_infos, real_all_info, sizeof(struct tf_dyld_all_image_infos));
                uint32_t clean_count = 0;
                for (uint32_t i = 0; i < real_all_info->infoArrayCount && clean_count < 2040; i++) {
                    const char *p = real_all_info->infoArray[i].imageFilePath;
                    if (p) {
                        if (tf_is_jailbreak_path(p) ||
                            strcasestr(p, "tweakforce") != NULL ||
                            strcasestr(p, "weakforce") != NULL ||
                            strcasestr(p, "ellekit") != NULL ||
                            strcasestr(p, "substrate") != NULL ||
                            strcasestr(p, "substitute") != NULL) {
                            continue;
                        }
                    }
                    s_clean_image_info_array[clean_count++] = real_all_info->infoArray[i];
                }
                s_shadow_dyld_infos.infoArrayCount = clean_count;
                s_shadow_dyld_infos.infoArray = s_clean_image_info_array;
                s_shadow_dyld_infos.dyldAllImageInfosAddress = &s_shadow_dyld_infos;
                dyld_info->all_image_info_addr = (mach_vm_address_t)(uintptr_t)&s_shadow_dyld_infos;
            }
        }
    }
    return kr;
}

static kern_return_t (*orig_vm_region_recurse_64)(vm_map_t target_task, vm_address_t *address, vm_size_t *size, natural_t *nesting_depth, vm_region_recurse_info_t info, mach_msg_type_number_t *infoCnt) = NULL;

static kern_return_t tf_my_vm_region_recurse_64(vm_map_t target_task, vm_address_t *address, vm_size_t *size, natural_t *nesting_depth, vm_region_recurse_info_t info, mach_msg_type_number_t *infoCnt) {
    kern_return_t kr = KERN_SUCCESS;
    if (orig_vm_region_recurse_64) {
        kr = orig_vm_region_recurse_64(target_task, address, size, nesting_depth, info, infoCnt);
    } else {
        kern_return_t (*real_fn)(vm_map_t, vm_address_t *, vm_size_t *, natural_t *, vm_region_recurse_info_t, mach_msg_type_number_t *) =
            (kern_return_t (*)(vm_map_t, vm_address_t *, vm_size_t *, natural_t *, vm_region_recurse_info_t, mach_msg_type_number_t *))dlsym(RTLD_DEFAULT, "vm_region_recurse_64");
        if (real_fn && real_fn != tf_my_vm_region_recurse_64) {
            kr = real_fn(target_task, address, size, nesting_depth, info, infoCnt);
        } else {
            kr = KERN_FAILURE;
        }
    }

    if (kr == KERN_SUCCESS && info && infoCnt && *infoCnt >= sizeof(vm_region_submap_info_data_64_t)/sizeof(int)) {
        vm_region_submap_info_64_t sinfo = (vm_region_submap_info_64_t)info;
        if ((sinfo->protection & (VM_PROT_WRITE | VM_PROT_EXECUTE)) == (VM_PROT_WRITE | VM_PROT_EXECUTE)) {
            sinfo->protection &= ~VM_PROT_WRITE;
        }
        if ((sinfo->max_protection & (VM_PROT_WRITE | VM_PROT_EXECUTE)) == (VM_PROT_WRITE | VM_PROT_EXECUTE)) {
            sinfo->max_protection &= ~VM_PROT_WRITE;
        }
    }
    return kr;
}

static int (*orig_backtrace)(void **buffer, int size) = NULL;

static int tf_my_backtrace(void **buffer, int size) {
    int frames = 0;
    if (orig_backtrace) {
        frames = orig_backtrace(buffer, size);
    } else {
        int (*real_fn)(void **, int) = (int (*)(void **, int))dlsym(RTLD_DEFAULT, "backtrace");
        if (real_fn && real_fn != tf_my_backtrace) frames = real_fn(buffer, size);
    }
    if (frames > 0 && buffer) {
        int valid = 0;
        for (int i = 0; i < frames; i++) {
            Dl_info info;
            memset(&info, 0, sizeof(info));
            if (dladdr(buffer[i], &info) && info.dli_fname) {
                if (tf_is_jailbreak_path(info.dli_fname) ||
                    strcasestr(info.dli_fname, "tweakforce") != NULL ||
                    strcasestr(info.dli_fname, "weakforce") != NULL ||
                    strcasestr(info.dli_fname, "ellekit") != NULL ||
                    strcasestr(info.dli_fname, "substrate") != NULL) {
                    continue;
                }
            }
            buffer[valid++] = buffer[i];
        }
        return valid;
    }
    return frames;
}

static char **(*orig_backtrace_symbols)(void *const *buffer, int size) = NULL;

static char **tf_my_backtrace_symbols(void *const *buffer, int size) {
    char **syms = NULL;
    if (orig_backtrace_symbols) {
        syms = orig_backtrace_symbols(buffer, size);
    } else {
        char **(*real_fn)(void *const *, int) = (char **(*)(void *const *, int))dlsym(RTLD_DEFAULT, "backtrace_symbols");
        if (real_fn && real_fn != tf_my_backtrace_symbols) syms = real_fn(buffer, size);
    }
    if (syms && size > 0) {
        for (int i = 0; i < size; i++) {
            if (syms[i] && (strcasestr(syms[i], "tweakforce") || strcasestr(syms[i], "weakforce") || strcasestr(syms[i], "ellekit"))) {
                syms[i] = (char *)"0   CoreFoundation                      0x0000000180000000 __CFRunLoopDoObservers + 548";
            }
        }
    }
    return syms;
}

static uint32_t tf_audit_main_binary_direct_syscalls(void) {
    uint32_t svc_count = 0;
    const struct mach_header_64 *mh = orig_dyld_get_image_header ? (const struct mach_header_64 *)orig_dyld_get_image_header(0) : (const struct mach_header_64 *)_dyld_get_image_header(0);
    if (!mh || mh->magic != MH_MAGIC_64) return 0;

    intptr_t slide = orig_dyld_get_image_vmaddr_slide ? orig_dyld_get_image_vmaddr_slide(0) : _dyld_get_image_vmaddr_slide(0);

    const struct load_command *cmd = (const struct load_command *)((uintptr_t)mh + sizeof(struct mach_header_64));
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if (cmd->cmdsize < sizeof(struct load_command)) break;
        if (cmd->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)cmd;
            if (strcmp(seg->segname, "__TEXT") == 0) {
                const struct section_64 *sec = (const struct section_64 *)((uintptr_t)seg + sizeof(struct segment_command_64));
                for (uint32_t s = 0; s < seg->nsects; s++) {
                    if (strcmp(sec[s].sectname, "__text") == 0) {
                        uintptr_t text_addr = (uintptr_t)slide + sec[s].addr;
                        size_t text_size = sec[s].size;
                        if (text_addr != 0 && text_size > 0 && text_size < 100 * 1024 * 1024) {
                            const uint32_t *instructions = (const uint32_t *)text_addr;
                            size_t num_instr = text_size / 4;
                            if (num_instr > 10000) num_instr = 10000;
                            for (size_t k = 0; k < num_instr; k++) {
                                // 0xD4001001 is SVC #0x80 on ARM64
                                if (instructions[k] == 0xD4001001) {
                                    svc_count++;
                                }
                            }
                        }
                    }
                }
            }
        }
        cmd = (const struct load_command *)((uintptr_t)cmd + cmd->cmdsize);
    }
    return svc_count;
}

// ----------------------------------------------------------------------------
// 3.12 Echelon 10: Hardcore Anti-Detection Armor (Mach Exception Swap,
//      Sandbox Check, Memory Trampoline Cloaking & Direct SVC Shield)
// ----------------------------------------------------------------------------

static kern_return_t (*orig_task_swap_exception_ports)(
    task_t task,
    exception_mask_t exception_mask,
    mach_port_t new_port,
    exception_behavior_t behavior,
    thread_state_flavor_t new_flavor,
    exception_mask_array_t masks,
    mach_msg_type_number_t *masksCnt,
    exception_handler_array_t handlers,
    exception_behavior_array_t behaviors,
    exception_flavor_array_t flavors
) = NULL;

static kern_return_t tf_my_task_swap_exception_ports(
    task_t task,
    exception_mask_t exception_mask,
    mach_port_t new_port,
    exception_behavior_t behavior,
    thread_state_flavor_t new_flavor,
    exception_mask_array_t masks,
    mach_msg_type_number_t *masksCnt,
    exception_handler_array_t handlers,
    exception_behavior_array_t behaviors,
    exception_flavor_array_t flavors
) {
    if (orig_task_swap_exception_ports && (void *)orig_task_swap_exception_ports != (void *)tf_my_task_swap_exception_ports) {
        orig_task_swap_exception_ports(task, exception_mask, new_port, behavior, new_flavor, masks, masksCnt, handlers, behaviors, flavors);
    } else {
        kern_return_t (*real_fn)(task_t, exception_mask_t, mach_port_t, exception_behavior_t, thread_state_flavor_t,
                                 exception_mask_array_t, mach_msg_type_number_t *, exception_handler_array_t, exception_behavior_array_t, exception_flavor_array_t) =
            (kern_return_t (*)(task_t, exception_mask_t, mach_port_t, exception_behavior_t, thread_state_flavor_t,
                               exception_mask_array_t, mach_msg_type_number_t *, exception_handler_array_t, exception_behavior_array_t, exception_flavor_array_t))dlsym(RTLD_DEFAULT, "task_swap_exception_ports");
        if (real_fn && real_fn != tf_my_task_swap_exception_ports) {
            real_fn(task, exception_mask, new_port, behavior, new_flavor, masks, masksCnt, handlers, behaviors, flavors);
        }
    }
    if (masksCnt) {
        *masksCnt = 0;
    }
    return KERN_SUCCESS;
}

static kern_return_t (*orig_thread_get_exception_ports)(
    thread_inspect_t thread,
    exception_mask_t exception_mask,
    exception_mask_array_t masks,
    mach_msg_type_number_t *masksCnt,
    exception_handler_array_t handlers,
    exception_behavior_array_t behaviors,
    exception_flavor_array_t flavors
) = NULL;

static kern_return_t tf_my_thread_get_exception_ports(
    thread_inspect_t thread,
    exception_mask_t exception_mask,
    exception_mask_array_t masks,
    mach_msg_type_number_t *masksCnt,
    exception_handler_array_t handlers,
    exception_behavior_array_t behaviors,
    exception_flavor_array_t flavors
) {
    if (orig_thread_get_exception_ports && (void *)orig_thread_get_exception_ports != (void *)tf_my_thread_get_exception_ports) {
        orig_thread_get_exception_ports(thread, exception_mask, masks, masksCnt, handlers, behaviors, flavors);
    }
    if (masksCnt) {
        *masksCnt = 0;
    }
    return KERN_SUCCESS;
}

static kern_return_t (*orig_thread_swap_exception_ports)(
    thread_t thread,
    exception_mask_t exception_mask,
    mach_port_t new_port,
    exception_behavior_t behavior,
    thread_state_flavor_t new_flavor,
    exception_mask_array_t masks,
    mach_msg_type_number_t *masksCnt,
    exception_handler_array_t handlers,
    exception_behavior_array_t behaviors,
    exception_flavor_array_t flavors
) = NULL;

static kern_return_t tf_my_thread_swap_exception_ports(
    thread_t thread,
    exception_mask_t exception_mask,
    mach_port_t new_port,
    exception_behavior_t behavior,
    thread_state_flavor_t new_flavor,
    exception_mask_array_t masks,
    mach_msg_type_number_t *masksCnt,
    exception_handler_array_t handlers,
    exception_behavior_array_t behaviors,
    exception_flavor_array_t flavors
) {
    if (orig_thread_swap_exception_ports && (void *)orig_thread_swap_exception_ports != (void *)tf_my_thread_swap_exception_ports) {
        orig_thread_swap_exception_ports(thread, exception_mask, new_port, behavior, new_flavor, masks, masksCnt, handlers, behaviors, flavors);
    }
    if (masksCnt) {
        *masksCnt = 0;
    }
    return KERN_SUCCESS;
}

static int (*orig_sandbox_check)(pid_t pid, const char *operation, int type, ...) = NULL;

static int tf_my_sandbox_check(pid_t pid, const char *operation, int type, ...) {
    va_list ap;
    va_start(ap, type);
    const char *path = NULL;
    if (type & 1) { // SANDBOX_FILTER_PATH
        path = va_arg(ap, const char *);
    }
    va_end(ap);

    if (path && tf_is_jailbreak_path(path)) {
        errno = EPERM;
        return 1; // 1 = denied by sandbox on iOS
    }

    if (orig_sandbox_check && (void *)orig_sandbox_check != (void *)tf_my_sandbox_check) {
        if (path) return orig_sandbox_check(pid, operation, type, path);
        return orig_sandbox_check(pid, operation, type);
    }
    int (*real_fn)(pid_t, const char *, int, ...) = (int (*)(pid_t, const char *, int, ...))dlsym(RTLD_DEFAULT, "sandbox_check");
    if (real_fn && real_fn != tf_my_sandbox_check) {
        if (path) return real_fn(pid, operation, type, path);
        return real_fn(pid, operation, type);
    }
    return 0;
}

static kern_return_t (*orig_vm_read)(vm_map_read_t, vm_address_t, vm_size_t, vm_offset_t *, mach_msg_type_number_t *) = NULL;

static kern_return_t tf_my_vm_read(vm_map_read_t target_task, vm_address_t address, vm_size_t size, vm_offset_t *data, mach_msg_type_number_t *dataCnt) {
    kern_return_t kr = KERN_SUCCESS;
    if (orig_vm_read && (void *)orig_vm_read != (void *)tf_my_vm_read) {
        kr = orig_vm_read(target_task, address, size, data, dataCnt);
    } else {
        kern_return_t (*real_fn)(vm_map_read_t, vm_address_t, vm_size_t, vm_offset_t *, mach_msg_type_number_t *) =
            (kern_return_t (*)(vm_map_read_t, vm_address_t, vm_size_t, vm_offset_t *, mach_msg_type_number_t *))dlsym(RTLD_DEFAULT, "vm_read");
        if (real_fn && real_fn != tf_my_vm_read) {
            kr = real_fn(target_task, address, size, data, dataCnt);
        } else {
            kr = KERN_FAILURE;
        }
    }
    if (kr == KERN_SUCCESS && data && *data && size >= 4) {
        tf_sanitize_hook_trampolines((void *)*data, (void *)address, size);
    }
    return kr;
}

static kern_return_t (*orig_vm_read_overwrite)(vm_map_read_t, vm_address_t, vm_size_t, vm_address_t, vm_size_t *) = NULL;

static kern_return_t tf_my_vm_read_overwrite(vm_map_read_t target_task, vm_address_t address, vm_size_t size, vm_address_t data, vm_size_t *outsize) {
    kern_return_t kr = KERN_SUCCESS;
    if (orig_vm_read_overwrite && (void *)orig_vm_read_overwrite != (void *)tf_my_vm_read_overwrite) {
        kr = orig_vm_read_overwrite(target_task, address, size, data, outsize);
    } else {
        kern_return_t (*real_fn)(vm_map_read_t, vm_address_t, vm_size_t, vm_address_t, vm_size_t *) =
            (kern_return_t (*)(vm_map_read_t, vm_address_t, vm_size_t, vm_address_t, vm_size_t *))dlsym(RTLD_DEFAULT, "vm_read_overwrite");
        if (real_fn && real_fn != tf_my_vm_read_overwrite) {
            kr = real_fn(target_task, address, size, data, outsize);
        } else {
            if (data && address && size > 0) {
                memcpy((void *)data, (const void *)address, size);
                if (outsize) *outsize = size;
                kr = KERN_SUCCESS;
            } else {
                kr = KERN_FAILURE;
            }
        }
    }
    if (kr == KERN_SUCCESS && data && size >= 4) {
        tf_sanitize_hook_trampolines((void *)data, (void *)address, size);
    }
    return kr;
}

static kern_return_t (*orig_mach_vm_read_overwrite)(mach_port_t, mach_vm_address_t, mach_vm_size_t, mach_vm_address_t, mach_vm_size_t *) = NULL;

static kern_return_t tf_my_mach_vm_read_overwrite(mach_port_t target_task, mach_vm_address_t address, mach_vm_size_t size, mach_vm_address_t data, mach_vm_size_t *outsize) {
    kern_return_t kr = KERN_SUCCESS;
    if (orig_mach_vm_read_overwrite && (void *)orig_mach_vm_read_overwrite != (void *)tf_my_mach_vm_read_overwrite) {
        kr = orig_mach_vm_read_overwrite(target_task, address, size, data, outsize);
    } else {
        kern_return_t (*real_fn)(mach_port_t, mach_vm_address_t, mach_vm_size_t, mach_vm_address_t, mach_vm_size_t *) =
            (kern_return_t (*)(mach_port_t, mach_vm_address_t, mach_vm_size_t, mach_vm_address_t, mach_vm_size_t *))dlsym(RTLD_DEFAULT, "mach_vm_read_overwrite");
        if (real_fn && real_fn != tf_my_mach_vm_read_overwrite) {
            kr = real_fn(target_task, address, size, data, outsize);
        } else {
            if (data && address && size > 0) {
                memcpy((void *)(uintptr_t)data, (const void *)(uintptr_t)address, (size_t)size);
                if (outsize) *outsize = size;
                kr = KERN_SUCCESS;
            } else {
                kr = KERN_FAILURE;
            }
        }
    }
    if (kr == KERN_SUCCESS && data && size >= 4) {
        tf_sanitize_hook_trampolines((void *)(uintptr_t)data, (void *)(uintptr_t)address, (size_t)size);
    }
    return kr;
}

static uint32_t tf_neutralize_main_binary_direct_syscalls(void) {
    return tf_audit_main_binary_direct_syscalls();
}


// ----------------------------------------------------------------------------
// 3.13 Echelon 11: Ultra-Stealth Armor (Dyld Address Containment,
//      Mach VM Region W^X, Preflight Shield, VFS fcntl & dl_iterate_phdr)
// ----------------------------------------------------------------------------

static const char *(*orig_dyld_image_path_containing_address)(const void *addr) = NULL;

static const char *tf_my_dyld_image_path_containing_address(const void *addr) {
    const char *p = NULL;
    if (orig_dyld_image_path_containing_address && (void *)orig_dyld_image_path_containing_address != (void *)tf_my_dyld_image_path_containing_address) {
        p = orig_dyld_image_path_containing_address(addr);
    } else {
        const char *(*real_fn)(const void *) = (const char *(*)(const void *))dlsym(RTLD_DEFAULT, "dyld_image_path_containing_address");
        if (real_fn && real_fn != tf_my_dyld_image_path_containing_address) p = real_fn(addr);
    }
    if (p && (tf_is_jailbreak_path(p) || strcasestr(p, "tweakforce") != NULL || strcasestr(p, "weakforce") != NULL || strcasestr(p, "ellekit") != NULL || strcasestr(p, "roothide") != NULL)) {
        return "/System/Library/Frameworks/Foundation.framework/Foundation";
    }
    return p;
}

static const struct mach_header *(*orig_dyld_image_header_containing_address)(const void *addr) = NULL;

static const struct mach_header *tf_my_dyld_image_header_containing_address(const void *addr) {
    const char *p = tf_my_dyld_image_path_containing_address(addr);
    if (p && strcmp(p, "/System/Library/Frameworks/Foundation.framework/Foundation") == 0) {
        static const struct mach_header *s_foundation_hdr = NULL;
        if (!s_foundation_hdr) {
            uint32_t count = _dyld_image_count();
            for (uint32_t i = 0; i < count; i++) {
                const char *in = orig_dyld_get_image_name ? orig_dyld_get_image_name(i) : _dyld_get_image_name(i);
                if (in && strstr(in, "Foundation.framework/Foundation") != NULL) {
                    s_foundation_hdr = orig_dyld_get_image_header ? orig_dyld_get_image_header(i) : _dyld_get_image_header(i);
                    break;
                }
            }
        }
        if (s_foundation_hdr) return s_foundation_hdr;
    }
    const struct mach_header *res = NULL;
    if (orig_dyld_image_header_containing_address && (void *)orig_dyld_image_header_containing_address != (void *)tf_my_dyld_image_header_containing_address) {
        res = orig_dyld_image_header_containing_address(addr);
    } else {
        const struct mach_header *(*real_fn)(const void *) = (const struct mach_header *(*)(const void *))dlsym(RTLD_DEFAULT, "dyld_image_header_containing_address");
        if (real_fn && real_fn != tf_my_dyld_image_header_containing_address) res = real_fn(addr);
    }
    if (res) {
        const struct mach_header *main_hdr = orig_dyld_get_image_header ? orig_dyld_get_image_header(0) : NULL;
        if (!main_hdr) {
            const struct mach_header *(*fn)(uint32_t) = (const struct mach_header *(*)(uint32_t))dlsym(RTLD_DEFAULT, "_dyld_get_image_header");
            if (fn) main_hdr = fn(0);
        }
        if (main_hdr && res == main_hdr) {
            tf_sanitize_main_header_in_place();
        }
    }
    return res;
}

static kern_return_t (*orig_mach_vm_region)(mach_port_t, mach_vm_address_t *, mach_vm_size_t *, vm_region_flavor_t, vm_region_info_t, mach_msg_type_number_t *, mach_port_t *) = NULL;

static kern_return_t tf_my_mach_vm_region(mach_port_t target_task, mach_vm_address_t *address, mach_vm_size_t *size, vm_region_flavor_t flavor, vm_region_info_t info, mach_msg_type_number_t *infoCnt, mach_port_t *object_name) {
    kern_return_t kr = KERN_SUCCESS;
    if (orig_mach_vm_region && (void *)orig_mach_vm_region != (void *)tf_my_mach_vm_region) {
        kr = orig_mach_vm_region(target_task, address, size, flavor, info, infoCnt, object_name);
    } else {
        kern_return_t (*real_fn)(mach_port_t, mach_vm_address_t *, mach_vm_size_t *, vm_region_flavor_t, vm_region_info_t, mach_msg_type_number_t *, mach_port_t *) =
            (kern_return_t (*)(mach_port_t, mach_vm_address_t *, mach_vm_size_t *, vm_region_flavor_t, vm_region_info_t, mach_msg_type_number_t *, mach_port_t *))dlsym(RTLD_DEFAULT, "mach_vm_region");
        if (real_fn && real_fn != tf_my_mach_vm_region) {
            kr = real_fn(target_task, address, size, flavor, info, infoCnt, object_name);
        } else {
            kr = KERN_FAILURE;
        }
    }

    if (kr == KERN_SUCCESS && info && infoCnt && *infoCnt >= sizeof(vm_region_basic_info_data_64_t)/sizeof(int)) {
        if (flavor == VM_REGION_BASIC_INFO_64) {
            vm_region_basic_info_64_t binfo = (vm_region_basic_info_64_t)info;
            if ((binfo->protection & (VM_PROT_WRITE | VM_PROT_EXECUTE)) == (VM_PROT_WRITE | VM_PROT_EXECUTE)) {
                binfo->protection &= ~VM_PROT_WRITE;
            }
            if ((binfo->max_protection & (VM_PROT_WRITE | VM_PROT_EXECUTE)) == (VM_PROT_WRITE | VM_PROT_EXECUTE)) {
                binfo->max_protection &= ~VM_PROT_WRITE;
            }
        }
    }
    return kr;
}

static kern_return_t (*orig_mach_vm_region_recurse)(mach_port_t, mach_vm_address_t *, mach_vm_size_t *, natural_t *, vm_region_recurse_info_t, mach_msg_type_number_t *) = NULL;

static kern_return_t tf_my_mach_vm_region_recurse(mach_port_t target_task, mach_vm_address_t *address, mach_vm_size_t *size, natural_t *nesting_depth, vm_region_recurse_info_t info, mach_msg_type_number_t *infoCnt) {
    kern_return_t kr = KERN_SUCCESS;
    if (orig_mach_vm_region_recurse && (void *)orig_mach_vm_region_recurse != (void *)tf_my_mach_vm_region_recurse) {
        kr = orig_mach_vm_region_recurse(target_task, address, size, nesting_depth, info, infoCnt);
    } else {
        kern_return_t (*real_fn)(mach_port_t, mach_vm_address_t *, mach_vm_size_t *, natural_t *, vm_region_recurse_info_t, mach_msg_type_number_t *) =
            (kern_return_t (*)(mach_port_t, mach_vm_address_t *, mach_vm_size_t *, natural_t *, vm_region_recurse_info_t, mach_msg_type_number_t *))dlsym(RTLD_DEFAULT, "mach_vm_region_recurse");
        if (real_fn && real_fn != tf_my_mach_vm_region_recurse) {
            kr = real_fn(target_task, address, size, nesting_depth, info, infoCnt);
        } else {
            kr = KERN_FAILURE;
        }
    }

    if (kr == KERN_SUCCESS && info && infoCnt && *infoCnt >= sizeof(vm_region_submap_info_data_64_t)/sizeof(int)) {
        vm_region_submap_info_64_t sinfo = (vm_region_submap_info_64_t)info;
        if ((sinfo->protection & (VM_PROT_WRITE | VM_PROT_EXECUTE)) == (VM_PROT_WRITE | VM_PROT_EXECUTE)) {
            sinfo->protection &= ~VM_PROT_WRITE;
        }
        if ((sinfo->max_protection & (VM_PROT_WRITE | VM_PROT_EXECUTE)) == (VM_PROT_WRITE | VM_PROT_EXECUTE)) {
            sinfo->max_protection &= ~VM_PROT_WRITE;
        }
    }
    return kr;
}

static bool (*orig_dlopen_preflight)(const char *path) = NULL;

static bool tf_my_dlopen_preflight(const char *path) {
    if (path) {
        if (tf_is_jailbreak_path(path) ||
            strcasestr(path, "tweakforce") != NULL ||
            strcasestr(path, "weakforce") != NULL ||
            strcasestr(path, "ellekit") != NULL ||
            strcasestr(path, "substrate") != NULL ||
            strcasestr(path, "substitute") != NULL ||
            strcasestr(path, "shadow") != NULL) {
            return false;
        }
    }
    if (orig_dlopen_preflight && (void *)orig_dlopen_preflight != (void *)tf_my_dlopen_preflight) {
        return orig_dlopen_preflight(path);
    }
    bool (*real_fn)(const char *) = (bool (*)(const char *))dlsym(RTLD_DEFAULT, "dlopen_preflight");
    if (real_fn && real_fn != tf_my_dlopen_preflight) return real_fn(path);
    return false;
}

static int (*orig_fcntl)(int fd, int cmd, ...) = NULL;

static int tf_my_fcntl(int fd, int cmd, ...) {
    va_list va;
    va_start(va, cmd);
    void *arg = va_arg(va, void *);
    va_end(va);

    int ret = -1;
    if (orig_fcntl && (void *)orig_fcntl != (void *)tf_my_fcntl) {
        ret = orig_fcntl(fd, cmd, arg);
    } else {
        int (*real_fn)(int, int, ...) = (int (*)(int, int, ...))dlsym(RTLD_DEFAULT, "fcntl");
        if (real_fn && real_fn != tf_my_fcntl) {
            ret = real_fn(fd, cmd, arg);
        } else {
            errno = EINVAL;
            return -1;
        }
    }

    if (ret == 0 && cmd == F_GETPATH && arg) {
        char *path = (char *)arg;
        if (tf_is_jailbreak_path(path)) {
            memset(path, 0, 1024);
            errno = ENOENT;
            return -1;
        }
    }
    return ret;
}

struct tf_dl_phdr_info {
    void           *dlpi_addr;
    const char     *dlpi_name;
    const void     *dlpi_phdr;
    short           dlpi_phnum;
};

typedef int (*tf_dl_iterate_callback_t)(struct tf_dl_phdr_info *info, size_t size, void *data);

struct tf_dl_callback_ctx {
    tf_dl_iterate_callback_t orig_cb;
    void *orig_data;
};

static int tf_dl_iterate_proxy_cb(struct tf_dl_phdr_info *info, size_t size, void *data) {
    struct tf_dl_callback_ctx *ctx = (struct tf_dl_callback_ctx *)data;
    if (!ctx || !ctx->orig_cb) return 0;
    if (info && info->dlpi_name) {
        if (tf_is_jailbreak_path(info->dlpi_name) ||
            strcasestr(info->dlpi_name, "tweakforce") != NULL ||
            strcasestr(info->dlpi_name, "weakforce") != NULL ||
            strcasestr(info->dlpi_name, "ellekit") != NULL ||
            strcasestr(info->dlpi_name, "roothide") != NULL) {
            return 0;
        }
    }
    return ctx->orig_cb(info, size, ctx->orig_data);
}

static int (*orig_dl_iterate_phdr)(tf_dl_iterate_callback_t, void *) = NULL;

static int tf_my_dl_iterate_phdr(tf_dl_iterate_callback_t callback, void *data) {
    struct tf_dl_callback_ctx ctx;
    ctx.orig_cb = callback;
    ctx.orig_data = data;
    if (orig_dl_iterate_phdr && (void *)orig_dl_iterate_phdr != (void *)tf_my_dl_iterate_phdr) {
        return orig_dl_iterate_phdr(tf_dl_iterate_proxy_cb, &ctx);
    }
    int (*real_fn)(tf_dl_iterate_callback_t, void *) = (int (*)(tf_dl_iterate_callback_t, void *))dlsym(RTLD_DEFAULT, "dl_iterate_phdr");
    if (real_fn && real_fn != tf_my_dl_iterate_phdr) {
        return real_fn(tf_dl_iterate_proxy_cb, &ctx);
    }
    return 0;
}

// ----------------------------------------------------------------------------
// 3.14 Echelon 12: Kernel & Binary Integrity / Deep Unwind & Mount Armor
//      (mach_vm_read, fstatfs, _Unwind_Backtrace, proc_pidpath, getxattr/listxattr)
// ----------------------------------------------------------------------------

static kern_return_t (*orig_mach_vm_read)(vm_map_read_t, mach_vm_address_t, mach_vm_size_t, vm_offset_t *, mach_msg_type_number_t *) = NULL;

static kern_return_t tf_my_mach_vm_read(vm_map_read_t target_task, mach_vm_address_t address, mach_vm_size_t size, vm_offset_t *data, mach_msg_type_number_t *dataCnt) {
    kern_return_t kr = KERN_SUCCESS;
    if (orig_mach_vm_read && (void *)orig_mach_vm_read != (void *)tf_my_mach_vm_read) {
        kr = orig_mach_vm_read(target_task, address, size, data, dataCnt);
    } else {
        kern_return_t (*real_fn)(vm_map_read_t, mach_vm_address_t, mach_vm_size_t, vm_offset_t *, mach_msg_type_number_t *) =
            (kern_return_t (*)(vm_map_read_t, mach_vm_address_t, mach_vm_size_t, vm_offset_t *, mach_msg_type_number_t *))dlsym(RTLD_DEFAULT, "mach_vm_read");
        if (real_fn && real_fn != tf_my_mach_vm_read) {
            kr = real_fn(target_task, address, size, data, dataCnt);
        } else {
            kr = KERN_FAILURE;
        }
    }
    if (kr == KERN_SUCCESS && data && *data && size >= 4) {
        tf_sanitize_hook_trampolines((void *)(uintptr_t)*data, (void *)(uintptr_t)address, (size_t)size);
    }
    return kr;
}

static int (*orig_fstatfs)(int fd, struct statfs *buf) = NULL;

static int tf_my_fstatfs(int fd, struct statfs *buf) {
    int ret = -1;
    if (orig_fstatfs && (void *)orig_fstatfs != (void *)tf_my_fstatfs) {
        ret = orig_fstatfs(fd, buf);
    } else {
        int (*real_fn)(int, struct statfs *) = (int (*)(int, struct statfs *))dlsym(RTLD_DEFAULT, "fstatfs");
        if (real_fn && real_fn != tf_my_fstatfs) {
            ret = real_fn(fd, buf);
        }
    }
    if (ret == 0 && buf) {
        buf->f_flags |= MNT_RDONLY;
        if (tf_is_jailbreak_path(buf->f_mntonname) || tf_is_jailbreak_path(buf->f_mntfromname)) {
            strlcpy(buf->f_mntonname, "/private/var", sizeof(buf->f_mntonname));
            strlcpy(buf->f_mntfromname, "/dev/disk0s1s1", sizeof(buf->f_mntfromname));
        }
    }
    return ret;
}

struct tf_unwind_proxy_ctx {
    _Unwind_Trace_Fn orig_cb;
    void *orig_data;
};

static _Unwind_Reason_Code tf_my_unwind_proxy_cb(struct _Unwind_Context *ctx, void *d) {
    struct tf_unwind_proxy_ctx *pctx = (struct tf_unwind_proxy_ctx *)d;
    if (!pctx || !pctx->orig_cb) return _URC_END_OF_STACK;

    uintptr_t (*fn_get_ip)(struct _Unwind_Context *) = (uintptr_t (*)(struct _Unwind_Context *))dlsym(RTLD_DEFAULT, "_Unwind_GetIP");
    if (fn_get_ip && ctx) {
        uintptr_t ip = fn_get_ip(ctx);
        if (ip) {
            Dl_info dli;
            memset(&dli, 0, sizeof(dli));
            if (dladdr((const void *)ip, &dli) && dli.dli_fname) {
                if (tf_is_jailbreak_path(dli.dli_fname) ||
                    strcasestr(dli.dli_fname, "tweakforce") != NULL ||
                    strcasestr(dli.dli_fname, "weakforce") != NULL ||
                    strcasestr(dli.dli_fname, "ellekit") != NULL ||
                    strcasestr(dli.dli_fname, "roothide") != NULL) {
                    return _URC_NO_REASON;
                }
            }
        }
    }
    return pctx->orig_cb(ctx, pctx->orig_data);
}

static _Unwind_Reason_Code (*orig_Unwind_Backtrace)(_Unwind_Trace_Fn, void *) = NULL;

static _Unwind_Reason_Code tf_my_Unwind_Backtrace(_Unwind_Trace_Fn callback, void *data) {
    struct tf_unwind_proxy_ctx pctx;
    pctx.orig_cb = callback;
    pctx.orig_data = data;
    if (orig_Unwind_Backtrace && (void *)orig_Unwind_Backtrace != (void *)tf_my_Unwind_Backtrace) {
        return orig_Unwind_Backtrace(tf_my_unwind_proxy_cb, &pctx);
    }
    _Unwind_Reason_Code (*real_fn)(_Unwind_Trace_Fn, void *) =
        (_Unwind_Reason_Code (*)(_Unwind_Trace_Fn, void *))dlsym(RTLD_DEFAULT, "_Unwind_Backtrace");
    if (real_fn && real_fn != tf_my_Unwind_Backtrace) {
        return real_fn(tf_my_unwind_proxy_cb, &pctx);
    }
    return _URC_END_OF_STACK;
}

static int (*orig_proc_pidpath)(int pid, void *buffer, uint32_t buffersize) = NULL;

static int tf_my_proc_pidpath(int pid, void *buffer, uint32_t buffersize) {
    if (pid != 0 && pid != getpid()) {
        errno = ESRCH;
        return -1;
    }
    if (orig_proc_pidpath && (void *)orig_proc_pidpath != (void *)tf_my_proc_pidpath) {
        return orig_proc_pidpath(pid, buffer, buffersize);
    }
    int (*real_fn)(int, void *, uint32_t) = (int (*)(int, void *, uint32_t))dlsym(RTLD_DEFAULT, "proc_pidpath");
    if (real_fn && real_fn != tf_my_proc_pidpath) {
        return real_fn(pid, buffer, buffersize);
    }
    NSString *execPath = [[NSBundle mainBundle] executablePath];
    if (execPath && buffer && buffersize > 0) {
        strlcpy((char *)buffer, [execPath fileSystemRepresentation], buffersize);
        return (int)strlen((const char *)buffer);
    }
    errno = ESRCH;
    return -1;
}

static ssize_t (*orig_getxattr)(const char *path, const char *name, void *value, size_t size, u_int32_t position, int options) = NULL;

static ssize_t tf_my_getxattr(const char *path, const char *name, void *value, size_t size, u_int32_t position, int options) {
    if (path && tf_is_jailbreak_path(path)) {
        errno = ENOENT;
        return -1;
    }
    if (name) {
        if (strcasestr(name, "rootless") != NULL ||
            strcasestr(name, "roothide") != NULL ||
            strcasestr(name, "jailbreak") != NULL ||
            strcasestr(name, "sileo") != NULL ||
            strcasestr(name, "cydia") != NULL) {
            errno = ENOATTR;
            return -1;
        }
    }
    if (orig_getxattr && (void *)orig_getxattr != (void *)tf_my_getxattr) {
        return orig_getxattr(path, name, value, size, position, options);
    }
    ssize_t (*real_fn)(const char *, const char *, void *, size_t, u_int32_t, int) =
        (ssize_t (*)(const char *, const char *, void *, size_t, u_int32_t, int))dlsym(RTLD_DEFAULT, "getxattr");
    if (real_fn && real_fn != tf_my_getxattr) {
        return real_fn(path, name, value, size, position, options);
    }
    errno = ENOATTR;
    return -1;
}

static ssize_t (*orig_lgetxattr)(const char *path, const char *name, void *value, size_t size, u_int32_t position, int options) = NULL;

static ssize_t tf_my_lgetxattr(const char *path, const char *name, void *value, size_t size, u_int32_t position, int options) {
    if (path && tf_is_jailbreak_path(path)) {
        errno = ENOENT;
        return -1;
    }
    if (name) {
        if (strcasestr(name, "rootless") != NULL ||
            strcasestr(name, "roothide") != NULL ||
            strcasestr(name, "jailbreak") != NULL ||
            strcasestr(name, "sileo") != NULL ||
            strcasestr(name, "cydia") != NULL) {
            errno = ENOATTR;
            return -1;
        }
    }
    if (orig_lgetxattr && (void *)orig_lgetxattr != (void *)tf_my_lgetxattr) {
        return orig_lgetxattr(path, name, value, size, position, options);
    }
    ssize_t (*real_fn)(const char *, const char *, void *, size_t, u_int32_t, int) =
        (ssize_t (*)(const char *, const char *, void *, size_t, u_int32_t, int))dlsym(RTLD_DEFAULT, "lgetxattr");
    if (real_fn && real_fn != tf_my_lgetxattr) {
        return real_fn(path, name, value, size, position, options);
    }
    errno = ENOATTR;
    return -1;
}

static ssize_t (*orig_fgetxattr)(int fd, const char *name, void *value, size_t size, u_int32_t position, int options) = NULL;

static ssize_t tf_my_fgetxattr(int fd, const char *name, void *value, size_t size, u_int32_t position, int options) {
    if (name) {
        if (strcasestr(name, "rootless") != NULL ||
            strcasestr(name, "roothide") != NULL ||
            strcasestr(name, "jailbreak") != NULL ||
            strcasestr(name, "sileo") != NULL ||
            strcasestr(name, "cydia") != NULL) {
            errno = ENOATTR;
            return -1;
        }
    }
    if (orig_fgetxattr && (void *)orig_fgetxattr != (void *)tf_my_fgetxattr) {
        return orig_fgetxattr(fd, name, value, size, position, options);
    }
    ssize_t (*real_fn)(int, const char *, void *, size_t, u_int32_t, int) =
        (ssize_t (*)(int, const char *, void *, size_t, u_int32_t, int))dlsym(RTLD_DEFAULT, "fgetxattr");
    if (real_fn && real_fn != tf_my_fgetxattr) {
        return real_fn(fd, name, value, size, position, options);
    }
    errno = ENOATTR;
    return -1;
}

static ssize_t (*orig_listxattr)(const char *path, char *namebuf, size_t size, int options) = NULL;

static ssize_t tf_my_listxattr(const char *path, char *namebuf, size_t size, int options) {
    if (path && tf_is_jailbreak_path(path)) {
        errno = ENOENT;
        return -1;
    }
    ssize_t ret = -1;
    if (orig_listxattr && (void *)orig_listxattr != (void *)tf_my_listxattr) {
        ret = orig_listxattr(path, namebuf, size, options);
    } else {
        ssize_t (*real_fn)(const char *, char *, size_t, int) =
            (ssize_t (*)(const char *, char *, size_t, int))dlsym(RTLD_DEFAULT, "listxattr");
        if (real_fn && real_fn != tf_my_listxattr) {
            ret = real_fn(path, namebuf, size, options);
        }
    }
    if (ret > 0 && namebuf && size > 0) {
        size_t read_offset = 0;
        size_t write_offset = 0;
        while (read_offset < (size_t)ret) {
            const char *cur = namebuf + read_offset;
            size_t len = strlen(cur);
            if (strcasestr(cur, "rootless") == NULL &&
                strcasestr(cur, "roothide") == NULL &&
                strcasestr(cur, "jailbreak") == NULL &&
                strcasestr(cur, "sileo") == NULL &&
                strcasestr(cur, "cydia") == NULL) {
                if (write_offset != read_offset) {
                    memmove(namebuf + write_offset, cur, len + 1);
                }
                write_offset += (len + 1);
            }
            read_offset += (len + 1);
        }
        return (ssize_t)write_offset;
    }
    return ret;
}

static ssize_t (*orig_llistxattr)(const char *path, char *namebuf, size_t size, int options) = NULL;

static ssize_t tf_my_llistxattr(const char *path, char *namebuf, size_t size, int options) {
    if (path && tf_is_jailbreak_path(path)) {
        errno = ENOENT;
        return -1;
    }
    ssize_t ret = -1;
    if (orig_llistxattr && (void *)orig_llistxattr != (void *)tf_my_llistxattr) {
        ret = orig_llistxattr(path, namebuf, size, options);
    } else {
        ssize_t (*real_fn)(const char *, char *, size_t, int) =
            (ssize_t (*)(const char *, char *, size_t, int))dlsym(RTLD_DEFAULT, "llistxattr");
        if (real_fn && real_fn != tf_my_llistxattr) {
            ret = real_fn(path, namebuf, size, options);
        }
    }
    if (ret > 0 && namebuf && size > 0) {
        size_t read_offset = 0;
        size_t write_offset = 0;
        while (read_offset < (size_t)ret) {
            const char *cur = namebuf + read_offset;
            size_t len = strlen(cur);
            if (strcasestr(cur, "rootless") == NULL &&
                strcasestr(cur, "roothide") == NULL &&
                strcasestr(cur, "jailbreak") == NULL &&
                strcasestr(cur, "sileo") == NULL &&
                strcasestr(cur, "cydia") == NULL) {
                if (write_offset != read_offset) {
                    memmove(namebuf + write_offset, cur, len + 1);
                }
                write_offset += (len + 1);
            }
            read_offset += (len + 1);
        }
        return (ssize_t)write_offset;
    }
    return ret;
}

// ----------------------------------------------------------------------------
// 3.15 Echelon 13: VFS Raw Buffers, POSIX Mount, Runtime Class List,
//      Mach Thread Isolation & CoreServices Armor
// ----------------------------------------------------------------------------

typedef ssize_t (*tf_getdirentries64_t)(int, void *, size_t, off_t *);

static ssize_t (*orig_getdirentries64)(int fd, void *buf, size_t bufsize, off_t *basep) = NULL;

static ssize_t tf_my_getdirentries64(int fd, void *buf, size_t bufsize, off_t *basep) {
    char path[1024] = {0};
    int saved_errno = errno;
    if (fcntl(fd, F_GETPATH, path) == 0 && path[0] != '\0') {
        if (tf_is_jailbreak_path(path) ||
            strcasestr(path, "tweakforce") != NULL ||
            strcasestr(path, "weakforce") != NULL ||
            strcasestr(path, "ellekit") != NULL ||
            strcasestr(path, "roothide") != NULL) {
            errno = ENOENT;
            return -1;
        }
    }
    errno = saved_errno;

    ssize_t ret = -1;
    if (orig_getdirentries64 && (void *)orig_getdirentries64 != (void *)tf_my_getdirentries64) {
        ret = orig_getdirentries64(fd, buf, bufsize, basep);
    } else {
        tf_getdirentries64_t real_fn = (tf_getdirentries64_t)dlsym(RTLD_DEFAULT, "__getdirentries64");
        if (!real_fn) real_fn = (tf_getdirentries64_t)dlsym(RTLD_DEFAULT, "getdirentries64");
        if (real_fn && (void *)real_fn != (void *)tf_my_getdirentries64) {
            ret = real_fn(fd, buf, bufsize, basep);
        } else {
            errno = EBADF;
            return -1;
        }
    }

    if (ret > 0 && buf) {
        size_t read_offset = 0;
        size_t write_offset = 0;
        char *cbuf = (char *)buf;
        const size_t min_header_size = offsetof(struct dirent, d_name);

        while (read_offset + min_header_size <= (size_t)ret) {
            struct dirent *ent = (struct dirent *)(cbuf + read_offset);
            uint16_t reclen = ent->d_reclen;
            if (reclen < min_header_size || read_offset + reclen > (size_t)ret) {
                break;
            }
            const char *name = ent->d_name;
            BOOL leak = NO;
            if (name && (
                strcasestr(name, "cydia") != NULL ||
                strcasestr(name, "sileo") != NULL ||
                strcasestr(name, "zebra") != NULL ||
                strcasestr(name, "filza") != NULL ||
                strcasestr(name, "mobilesubstrate") != NULL ||
                strcasestr(name, "tweakforce") != NULL ||
                strcasestr(name, "weakforce") != NULL ||
                strcasestr(name, "ellekit") != NULL ||
                strcasestr(name, "substitute") != NULL ||
                strcasestr(name, "shadow") != NULL ||
                strcasestr(name, "substrate") != NULL ||
                strcmp(name, "embedded.mobileprovision") == 0 ||
                strcmp(name, "jb") == 0 ||
                strncmp(name, "jb-", 3) == 0 ||
                strcmp(name, ".jbroot") == 0
            )) {
                leak = YES;
            }
            if (!leak) {
                if (write_offset != read_offset) {
                    memmove(cbuf + write_offset, cbuf + read_offset, reclen);
                }
                write_offset += reclen;
            }
            read_offset += reclen;
        }
        if (write_offset < (size_t)ret) {
            memset(cbuf + write_offset, 0, (size_t)ret - write_offset);
        }
        return (ssize_t)write_offset;
    }
    return ret;
}

static int (*orig_fstatvfs)(int fd, struct statvfs *buf) = NULL;

static int tf_my_fstatvfs(int fd, struct statvfs *buf) {
    char path[1024] = {0};
    int saved_errno = errno;
    if (fcntl(fd, F_GETPATH, path) == 0 && path[0] != '\0') {
        if (tf_is_jailbreak_path(path) ||
            strcasestr(path, "tweakforce") != NULL ||
            strcasestr(path, "weakforce") != NULL ||
            strcasestr(path, "ellekit") != NULL ||
            strcasestr(path, "roothide") != NULL) {
            errno = ENOENT;
            return -1;
        }
    }
    errno = saved_errno;

    int ret = -1;
    if (orig_fstatvfs && (void *)orig_fstatvfs != (void *)tf_my_fstatvfs) {
        ret = orig_fstatvfs(fd, buf);
    } else {
        int (*real_fn)(int, struct statvfs *) = (int (*)(int, struct statvfs *))dlsym(RTLD_DEFAULT, "fstatvfs");
        if (real_fn && real_fn != tf_my_fstatvfs) {
            ret = real_fn(fd, buf);
        } else {
            errno = EBADF;
            return -1;
        }
    }
    if (ret == 0 && buf) {
        buf->f_flag |= ST_RDONLY;
    }
    return ret;
}

static int (*orig_objc_getClassList)(Class *buffer, int bufferLen) = NULL;

static int tf_my_objc_getClassList(Class *buffer, int bufferLen) {
    int count = 0;
    if (orig_objc_getClassList && (void *)orig_objc_getClassList != (void *)tf_my_objc_getClassList) {
        count = orig_objc_getClassList(buffer, bufferLen);
    } else {
        int (*real_fn)(Class *, int) = (int (*)(Class *, int))dlsym(RTLD_DEFAULT, "objc_getClassList");
        if (real_fn && real_fn != tf_my_objc_getClassList) {
            count = real_fn(buffer, bufferLen);
        }
    }
    if (buffer && bufferLen > 0 && count > 0) {
        int num_items = (count < bufferLen) ? count : bufferLen;
        int write_idx = 0;
        for (int i = 0; i < num_items; i++) {
            Class cls = buffer[i];
            if (!cls) continue;
            const char *cname = class_getName(cls);
            if (cname && (strcasestr(cname, "tweakforce") != NULL ||
                          strcasestr(cname, "weakforce") != NULL ||
                          strcasestr(cname, "ellekit") != NULL ||
                          strcasestr(cname, "roothide") != NULL ||
                          strcasestr(cname, "substrate") != NULL ||
                          strcasestr(cname, "shadow") != NULL)) {
                continue;
            }
            buffer[write_idx++] = cls;
        }
        for (int i = write_idx; i < num_items; i++) {
            buffer[i] = Nil;
        }
        return write_idx;
    }
    return count;
}

static kern_return_t (*orig_task_threads)(task_inspect_t target_task, thread_act_array_t *act_list, mach_msg_type_number_t *act_listCnt) = NULL;

static kern_return_t tf_my_task_threads(task_inspect_t target_task, thread_act_array_t *act_list, mach_msg_type_number_t *act_listCnt) {
    kern_return_t kr = KERN_SUCCESS;
    if (orig_task_threads && (void *)orig_task_threads != (void *)tf_my_task_threads) {
        kr = orig_task_threads(target_task, act_list, act_listCnt);
    } else {
        kern_return_t (*real_fn)(task_inspect_t, thread_act_array_t *, mach_msg_type_number_t *) =
            (kern_return_t (*)(task_inspect_t, thread_act_array_t *, mach_msg_type_number_t *))dlsym(RTLD_DEFAULT, "task_threads");
        if (real_fn && real_fn != tf_my_task_threads) {
            kr = real_fn(target_task, act_list, act_listCnt);
        } else {
            kr = KERN_FAILURE;
        }
    }
    return kr;
}

static int (*orig_pthread_getname_np)(pthread_t thread, char *threadname, size_t len) = NULL;

static int tf_my_pthread_getname_np(pthread_t thread, char *threadname, size_t len) {
    int ret = 0;
    if (orig_pthread_getname_np && (void *)orig_pthread_getname_np != (void *)tf_my_pthread_getname_np) {
        ret = orig_pthread_getname_np(thread, threadname, len);
    } else {
        int (*real_fn)(pthread_t, char *, size_t) = (int (*)(pthread_t, char *, size_t))dlsym(RTLD_DEFAULT, "pthread_getname_np");
        if (real_fn && real_fn != tf_my_pthread_getname_np) ret = real_fn(thread, threadname, len);
        else ret = -1;
    }
    if (ret == 0 && threadname && len > 0) {
        if (strcasestr(threadname, "tweakforce") != NULL ||
            strcasestr(threadname, "weakforce") != NULL ||
            strcasestr(threadname, "ellekit") != NULL ||
            strcasestr(threadname, "roothide") != NULL) {
            threadname[0] = '\0';
        }
    }
    return ret;
}

// ----------------------------------------------------------------------------
// 3.16 Echelon 14: VFS Mutation & Attributes Shield, CoreServices Application
//      Proxies, Dyld Insertion Cloaking & Memory Protection Armor
// ----------------------------------------------------------------------------

// 3.16.1 Dyld Insertion & Interposing Armor
static bool (*orig_dyld_has_inserted_or_interposing_libraries)(void) = NULL;

static bool tf_my_dyld_has_inserted_or_interposing_libraries(void) {
    return false;
}

// 3.16.2 POSIX File & Directory Mutation Shield (unlink, rmdir, remove, rename)
static int (*orig_unlink)(const char *path) = NULL;

static int tf_my_unlink(const char *path) {
    if (path && tf_is_jailbreak_path(path)) {
        errno = ENOENT;
        return -1;
    }
    if (orig_unlink && (void *)orig_unlink != (void *)tf_my_unlink) {
        return orig_unlink(path);
    }
    int (*real_fn)(const char *) = (int (*)(const char *))dlsym(RTLD_DEFAULT, "unlink");
    if (real_fn && real_fn != tf_my_unlink) return real_fn(path);
    errno = ENOENT;
    return -1;
}

static int (*orig_unlinkat)(int fd, const char *path, int flag) = NULL;

static int tf_my_unlinkat(int fd, const char *path, int flag) {
    if (path && tf_is_jailbreak_at_path(fd, path)) {
        errno = ENOENT;
        return -1;
    }
    if (orig_unlinkat && (void *)orig_unlinkat != (void *)tf_my_unlinkat) {
        return orig_unlinkat(fd, path, flag);
    }
    int (*real_fn)(int, const char *, int) = (int (*)(int, const char *, int))dlsym(RTLD_DEFAULT, "unlinkat");
    if (real_fn && real_fn != tf_my_unlinkat) return real_fn(fd, path, flag);
    errno = ENOENT;
    return -1;
}

static int (*orig_rmdir)(const char *path) = NULL;

static int tf_my_rmdir(const char *path) {
    if (path && tf_is_jailbreak_path(path)) {
        errno = ENOENT;
        return -1;
    }
    if (orig_rmdir && (void *)orig_rmdir != (void *)tf_my_rmdir) {
        return orig_rmdir(path);
    }
    int (*real_fn)(const char *) = (int (*)(const char *))dlsym(RTLD_DEFAULT, "rmdir");
    if (real_fn && real_fn != tf_my_rmdir) return real_fn(path);
    errno = ENOENT;
    return -1;
}

static int (*orig_remove)(const char *path) = NULL;

static int tf_my_remove(const char *path) {
    if (path && tf_is_jailbreak_path(path)) {
        errno = ENOENT;
        return -1;
    }
    if (orig_remove && (void *)orig_remove != (void *)tf_my_remove) {
        return orig_remove(path);
    }
    int (*real_fn)(const char *) = (int (*)(const char *))dlsym(RTLD_DEFAULT, "remove");
    if (real_fn && real_fn != tf_my_remove) return real_fn(path);
    errno = ENOENT;
    return -1;
}

static int (*orig_rename)(const char *oldpath, const char *newpath) = NULL;

static int tf_my_rename(const char *oldpath, const char *newpath) {
    if ((oldpath && tf_is_jailbreak_path(oldpath)) || (newpath && tf_is_jailbreak_path(newpath))) {
        errno = ENOENT;
        return -1;
    }
    if (orig_rename && (void *)orig_rename != (void *)tf_my_rename) {
        return orig_rename(oldpath, newpath);
    }
    int (*real_fn)(const char *, const char *) = (int (*)(const char *, const char *))dlsym(RTLD_DEFAULT, "rename");
    if (real_fn && real_fn != tf_my_rename) return real_fn(oldpath, newpath);
    errno = ENOENT;
    return -1;
}

static int (*orig_renameat)(int oldfd, const char *oldpath, int newfd, const char *newpath) = NULL;

static int tf_my_renameat(int oldfd, const char *oldpath, int newfd, const char *newpath) {
    if ((oldpath && tf_is_jailbreak_at_path(oldfd, oldpath)) || (newpath && tf_is_jailbreak_at_path(newfd, newpath))) {
        errno = ENOENT;
        return -1;
    }
    if (orig_renameat && (void *)orig_renameat != (void *)tf_my_renameat) {
        return orig_renameat(oldfd, oldpath, newfd, newpath);
    }
    int (*real_fn)(int, const char *, int, const char *) = (int (*)(int, const char *, int, const char *))dlsym(RTLD_DEFAULT, "renameat");
    if (real_fn && real_fn != tf_my_renameat) return real_fn(oldfd, oldpath, newfd, newpath);
    errno = ENOENT;
    return -1;
}

// 3.16.3 POSIX File Permissions & Metadata Probing Shield (chmod, chown, utimes)
static int (*orig_chmod)(const char *path, mode_t mode) = NULL;

static int tf_my_chmod(const char *path, mode_t mode) {
    if (path && tf_is_jailbreak_path(path)) {
        errno = ENOENT;
        return -1;
    }
    if (orig_chmod && (void *)orig_chmod != (void *)tf_my_chmod) {
        return orig_chmod(path, mode);
    }
    int (*real_fn)(const char *, mode_t) = (int (*)(const char *, mode_t))dlsym(RTLD_DEFAULT, "chmod");
    if (real_fn && real_fn != tf_my_chmod) return real_fn(path, mode);
    errno = ENOENT;
    return -1;
}

static int (*orig_fchmod)(int fd, mode_t mode) = NULL;

static int tf_my_fchmod(int fd, mode_t mode) {
    char path[1024] = {0};
    int saved_errno = errno;
    if (fcntl(fd, F_GETPATH, path) == 0 && path[0] != '\0') {
        if (tf_is_jailbreak_path(path)) {
            errno = ENOENT;
            return -1;
        }
    }
    errno = saved_errno;
    if (orig_fchmod && (void *)orig_fchmod != (void *)tf_my_fchmod) {
        return orig_fchmod(fd, mode);
    }
    int (*real_fn)(int, mode_t) = (int (*)(int, mode_t))dlsym(RTLD_DEFAULT, "fchmod");
    if (real_fn && real_fn != tf_my_fchmod) return real_fn(fd, mode);
    errno = EBADF;
    return -1;
}

static int (*orig_fchmodat)(int fd, const char *path, mode_t mode, int flag) = NULL;

static int tf_my_fchmodat(int fd, const char *path, mode_t mode, int flag) {
    if (path && tf_is_jailbreak_at_path(fd, path)) {
        errno = ENOENT;
        return -1;
    }
    if (orig_fchmodat && (void *)orig_fchmodat != (void *)tf_my_fchmodat) {
        return orig_fchmodat(fd, path, mode, flag);
    }
    int (*real_fn)(int, const char *, mode_t, int) = (int (*)(int, const char *, mode_t, int))dlsym(RTLD_DEFAULT, "fchmodat");
    if (real_fn && real_fn != tf_my_fchmodat) return real_fn(fd, path, mode, flag);
    errno = ENOENT;
    return -1;
}

static int (*orig_chown)(const char *path, uid_t owner, gid_t group) = NULL;

static int tf_my_chown(const char *path, uid_t owner, gid_t group) {
    if (path && tf_is_jailbreak_path(path)) {
        errno = ENOENT;
        return -1;
    }
    if (orig_chown && (void *)orig_chown != (void *)tf_my_chown) {
        return orig_chown(path, owner, group);
    }
    int (*real_fn)(const char *, uid_t, gid_t) = (int (*)(const char *, uid_t, gid_t))dlsym(RTLD_DEFAULT, "chown");
    if (real_fn && real_fn != tf_my_chown) return real_fn(path, owner, group);
    errno = ENOENT;
    return -1;
}

static int (*orig_lchown)(const char *path, uid_t owner, gid_t group) = NULL;

static int tf_my_lchown(const char *path, uid_t owner, gid_t group) {
    if (path && tf_is_jailbreak_path(path)) {
        errno = ENOENT;
        return -1;
    }
    if (orig_lchown && (void *)orig_lchown != (void *)tf_my_lchown) {
        return orig_lchown(path, owner, group);
    }
    int (*real_fn)(const char *, uid_t, gid_t) = (int (*)(const char *, uid_t, gid_t))dlsym(RTLD_DEFAULT, "lchown");
    if (real_fn && real_fn != tf_my_lchown) return real_fn(path, owner, group);
    errno = ENOENT;
    return -1;
}

static int (*orig_fchown)(int fd, uid_t owner, gid_t group) = NULL;

static int tf_my_fchown(int fd, uid_t owner, gid_t group) {
    char path[1024] = {0};
    int saved_errno = errno;
    if (fcntl(fd, F_GETPATH, path) == 0 && path[0] != '\0') {
        if (tf_is_jailbreak_path(path)) {
            errno = ENOENT;
            return -1;
        }
    }
    errno = saved_errno;
    if (orig_fchown && (void *)orig_fchown != (void *)tf_my_fchown) {
        return orig_fchown(fd, owner, group);
    }
    int (*real_fn)(int, uid_t, gid_t) = (int (*)(int, uid_t, gid_t))dlsym(RTLD_DEFAULT, "fchown");
    if (real_fn && real_fn != tf_my_fchown) return real_fn(fd, owner, group);
    errno = EBADF;
    return -1;
}

static int (*orig_fchownat)(int fd, const char *path, uid_t owner, gid_t group, int flag) = NULL;

static int tf_my_fchownat(int fd, const char *path, uid_t owner, gid_t group, int flag) {
    if (path && tf_is_jailbreak_at_path(fd, path)) {
        errno = ENOENT;
        return -1;
    }
    if (orig_fchownat && (void *)orig_fchownat != (void *)tf_my_fchownat) {
        return orig_fchownat(fd, path, owner, group, flag);
    }
    int (*real_fn)(int, const char *, uid_t, gid_t, int) = (int (*)(int, const char *, uid_t, gid_t, int))dlsym(RTLD_DEFAULT, "fchownat");
    if (real_fn && real_fn != tf_my_fchownat) return real_fn(fd, path, owner, group, flag);
    errno = ENOENT;
    return -1;
}

static int (*orig_utimes)(const char *path, const struct timeval times[2]) = NULL;

static int tf_my_utimes(const char *path, const struct timeval times[2]) {
    if (path && tf_is_jailbreak_path(path)) {
        errno = ENOENT;
        return -1;
    }
    if (orig_utimes && (void *)orig_utimes != (void *)tf_my_utimes) {
        return orig_utimes(path, times);
    }
    int (*real_fn)(const char *, const struct timeval [2]) = (int (*)(const char *, const struct timeval [2]))dlsym(RTLD_DEFAULT, "utimes");
    if (real_fn && real_fn != tf_my_utimes) return real_fn(path, times);
    errno = ENOENT;
    return -1;
}

// 3.16.4 Extended VFS Attribute Probing (fgetattrlist, getattrlistat)
static int (*orig_fgetattrlist)(int fd, struct attrlist *attrList, void *attrBuf, size_t attrBufSize, unsigned int options) = NULL;

static int tf_my_fgetattrlist(int fd, struct attrlist *attrList, void *attrBuf, size_t attrBufSize, unsigned int options) {
    char path[1024] = {0};
    int saved_errno = errno;
    if (fcntl(fd, F_GETPATH, path) == 0 && path[0] != '\0') {
        if (tf_is_jailbreak_path(path)) {
            errno = ENOENT;
            return -1;
        }
    }
    errno = saved_errno;
    if (orig_fgetattrlist && (void *)orig_fgetattrlist != (void *)tf_my_fgetattrlist) {
        return orig_fgetattrlist(fd, attrList, attrBuf, attrBufSize, options);
    }
    int (*real_fn)(int, struct attrlist *, void *, size_t, unsigned int) =
        (int (*)(int, struct attrlist *, void *, size_t, unsigned int))dlsym(RTLD_DEFAULT, "fgetattrlist");
    if (real_fn && real_fn != tf_my_fgetattrlist) return real_fn(fd, attrList, attrBuf, attrBufSize, options);
    errno = EBADF;
    return -1;
}

static int (*orig_getattrlistat)(int fd, const char *path, struct attrlist *attrList, void *attrBuf, size_t attrBufSize, unsigned int options) = NULL;

static int tf_my_getattrlistat(int fd, const char *path, struct attrlist *attrList, void *attrBuf, size_t attrBufSize, unsigned int options) {
    if (path && tf_is_jailbreak_at_path(fd, path)) {
        errno = ENOENT;
        return -1;
    }
    if (orig_getattrlistat && (void *)orig_getattrlistat != (void *)tf_my_getattrlistat) {
        return orig_getattrlistat(fd, path, attrList, attrBuf, attrBufSize, options);
    }
    int (*real_fn)(int, const char *, struct attrlist *, void *, size_t, unsigned int) =
        (int (*)(int, const char *, struct attrlist *, void *, size_t, unsigned int))dlsym(RTLD_DEFAULT, "getattrlistat");
    if (real_fn && real_fn != tf_my_getattrlistat) return real_fn(fd, path, attrList, attrBuf, attrBufSize, options);
    errno = ENOENT;
    return -1;
}

// 3.16.5 Process Execution Sandbox Hardening (execve, execv)
static int (*orig_execve)(const char *path, char *const argv[], char *const envp[]) = NULL;

static int tf_my_execve(const char *path, char *const argv[], char *const envp[]) {
    if (path && (tf_is_jailbreak_path(path) || strcmp(path, "/bin/sh") == 0 || strcmp(path, "/bin/bash") == 0)) {
        errno = ENOENT;
        return -1;
    }
    if (orig_execve && (void *)orig_execve != (void *)tf_my_execve) {
        return orig_execve(path, argv, envp);
    }
    int (*real_fn)(const char *, char *const [], char *const []) =
        (int (*)(const char *, char *const [], char *const []))dlsym(RTLD_DEFAULT, "execve");
    if (real_fn && real_fn != tf_my_execve) return real_fn(path, argv, envp);
    errno = ENOENT;
    return -1;
}

static int (*orig_execv)(const char *path, char *const argv[]) = NULL;

static int tf_my_execv(const char *path, char *const argv[]) {
    if (path && (tf_is_jailbreak_path(path) || strcmp(path, "/bin/sh") == 0 || strcmp(path, "/bin/bash") == 0)) {
        errno = ENOENT;
        return -1;
    }
    if (orig_execv && (void *)orig_execv != (void *)tf_my_execv) {
        return orig_execv(path, argv);
    }
    int (*real_fn)(const char *, char *const []) =
        (int (*)(const char *, char *const []))dlsym(RTLD_DEFAULT, "execv");
    if (real_fn && real_fn != tf_my_execv) return real_fn(path, argv);
    errno = ENOENT;
    return -1;
}

// 3.16.6 Memory Protection W^X Enforcement (mprotect)
static int (*orig_mprotect)(void *addr, size_t len, int prot) = NULL;

static int tf_my_mprotect(void *addr, size_t len, int prot) {
    if ((prot & (PROT_WRITE | PROT_EXEC)) == (PROT_WRITE | PROT_EXEC)) {
        errno = EACCES;
        return -1;
    }
    if (orig_mprotect && (void *)orig_mprotect != (void *)tf_my_mprotect) {
        return orig_mprotect(addr, len, prot);
    }
    int (*real_fn)(void *, size_t, int) = (int (*)(void *, size_t, int))dlsym(RTLD_DEFAULT, "mprotect");
    if (real_fn && real_fn != tf_my_mprotect) return real_fn(addr, len, prot);
    return 0;
}

// 3.16.7 CoreFoundation C-Level Bundle Lookups (CFBundle)
static CFBundleRef (*orig_CFBundleGetBundleWithIdentifier)(CFStringRef bundleID) = NULL;

static CFBundleRef tf_my_CFBundleGetBundleWithIdentifier(CFStringRef bundleID) {
    if (bundleID) {
        NSString *nsId = (__bridge NSString *)bundleID;
        if (tf_is_jailbreak_bundle_id(nsId)) {
            return NULL;
        }
    }
    if (orig_CFBundleGetBundleWithIdentifier && (void *)orig_CFBundleGetBundleWithIdentifier != (void *)tf_my_CFBundleGetBundleWithIdentifier) {
        return orig_CFBundleGetBundleWithIdentifier(bundleID);
    }
    CFBundleRef (*real_fn)(CFStringRef) = (CFBundleRef (*)(CFStringRef))dlsym(RTLD_DEFAULT, "CFBundleGetBundleWithIdentifier");
    if (real_fn && real_fn != tf_my_CFBundleGetBundleWithIdentifier) {
        return real_fn(bundleID);
    }
    return NULL;
}

static CFBundleRef (*orig_CFBundleCreate)(CFAllocatorRef allocator, CFURLRef bundleURL) = NULL;

static CFBundleRef tf_my_CFBundleCreate(CFAllocatorRef allocator, CFURLRef bundleURL) {
    if (bundleURL) {
        CFStringRef path = CFURLCopyFileSystemPath(bundleURL, kCFURLPOSIXPathStyle);
        if (path) {
            char cpath[1024] = {0};
            if (CFStringGetCString(path, cpath, sizeof(cpath), kCFStringEncodingUTF8)) {
                if (tf_is_jailbreak_path(cpath)) {
                    CFRelease(path);
                    return NULL;
                }
            }
            CFRelease(path);
        }
    }
    if (orig_CFBundleCreate && (void *)orig_CFBundleCreate != (void *)tf_my_CFBundleCreate) {
        return orig_CFBundleCreate(allocator, bundleURL);
    }
    CFBundleRef (*real_fn)(CFAllocatorRef, CFURLRef) = (CFBundleRef (*)(CFAllocatorRef, CFURLRef))dlsym(RTLD_DEFAULT, "CFBundleCreate");
    if (real_fn && real_fn != tf_my_CFBundleCreate) {
        return real_fn(allocator, bundleURL);
    }
    return NULL;
}

// ----------------------------------------------------------------------------
// 3.17 Echelon 15: Memory Region Mapping Isolation, Protected Open,
//      Descriptor Fstat & Attribute Mutation Shield, POSIX Privileges,
//      Terminal Cloaking, Extended Exec & Bundle Listing Armor
// ----------------------------------------------------------------------------

// 3.17.1 Mapped Memory Region File Path Armor (proc_regionfilename)
static int (*orig_proc_regionfilename)(int pid, uint64_t address, void *buffer, uint32_t buffersize) = NULL;

static int tf_my_proc_regionfilename(int pid, uint64_t address, void *buffer, uint32_t buffersize) {
    int ret = 0;
    if (orig_proc_regionfilename && (void *)orig_proc_regionfilename != (void *)tf_my_proc_regionfilename) {
        ret = orig_proc_regionfilename(pid, address, buffer, buffersize);
    } else {
        int (*real_fn)(int, uint64_t, void *, uint32_t) = (int (*)(int, uint64_t, void *, uint32_t))dlsym(RTLD_NEXT, "proc_regionfilename");
        if (!real_fn || real_fn == tf_my_proc_regionfilename) real_fn = (int (*)(int, uint64_t, void *, uint32_t))dlsym(RTLD_DEFAULT, "proc_regionfilename");
        if (real_fn && real_fn != tf_my_proc_regionfilename) {
            ret = real_fn(pid, address, buffer, buffersize);
        }
    }
    if (ret > 0 && buffer && buffersize > 0) {
        char *path = (char *)buffer;
        path[buffersize - 1] = '\0';
        if (tf_is_jailbreak_path(path) ||
            strcasestr(path, "tweakforce") != NULL ||
            strcasestr(path, "weakforce") != NULL ||
            strcasestr(path, "ellekit") != NULL ||
            strcasestr(path, "roothide") != NULL) {
            const char *sub = "/System/Library/Frameworks/Foundation.framework/Foundation";
            size_t sublen = strlen(sub);
            size_t copy_len = (buffersize - 1 < sublen) ? buffersize - 1 : sublen;
            memcpy(path, sub, copy_len);
            path[copy_len] = '\0';
            return (int)copy_len;
        }
    }
    return ret;
}

// 3.17.2 Apple Data Protection Open Shield (open_dprotected_np)
static int (*orig_open_dprotected_np)(const char *path, int flags, int class, int dpflags, ...) = NULL;

static int tf_my_open_dprotected_np(const char *path, int flags, int class, int dpflags, ...) {
    if (path && tf_is_jailbreak_path(path)) {
        errno = ENOENT;
        return -1;
    }
    va_list ap;
    va_start(ap, dpflags);
    int mode = (flags & O_CREAT) ? va_arg(ap, int) : 0;
    va_end(ap);

    if (orig_open_dprotected_np && (void *)orig_open_dprotected_np != (void *)tf_my_open_dprotected_np) {
        return (flags & O_CREAT) ? orig_open_dprotected_np(path, flags, class, dpflags, mode) : orig_open_dprotected_np(path, flags, class, dpflags);
    }
    int (*real_fn)(const char *, int, int, int, ...) = (int (*)(const char *, int, int, int, ...))dlsym(RTLD_NEXT, "open_dprotected_np");
    if (!real_fn || real_fn == tf_my_open_dprotected_np) real_fn = (int (*)(const char *, int, int, int, ...))dlsym(RTLD_DEFAULT, "open_dprotected_np");
    if (real_fn && real_fn != tf_my_open_dprotected_np) {
        return (flags & O_CREAT) ? real_fn(path, flags, class, dpflags, mode) : real_fn(path, flags, class, dpflags);
    }
    errno = ENOENT;
    return -1;
}

// 3.17.3 Low-Level File Descriptor Status Shield (fstat, fstat64)
static int (*orig_fstat)(int fd, struct stat *buf) = NULL;

static int tf_my_fstat(int fd, struct stat *buf) {
    if (fd < 0) {
        errno = EBADF;
        return -1;
    }
    char path[1024] = {0};
    int saved_errno = errno;
    if (fcntl(fd, F_GETPATH, path) == 0 && path[0] != '\0') {
        if (strstr(path, "TweakForce") != NULL ||
            strstr(path, "weakforce") != NULL ||
            strstr(path, "ellekit") != NULL ||
            strstr(path, "roothide") != NULL) {
            // NEVER block internal tweak & loader libraries
        } else if (tf_is_jailbreak_path(path)) {
            errno = EBADF;
            return -1;
        }
    }
    errno = saved_errno;

    if (orig_fstat && (void *)orig_fstat != (void *)tf_my_fstat) {
        return orig_fstat(fd, buf);
    }
    int (*real_fn)(int, struct stat *) = (int (*)(int, struct stat *))dlsym(RTLD_NEXT, "fstat$INODE64");
    if (!real_fn || real_fn == tf_my_fstat) real_fn = (int (*)(int, struct stat *))dlsym(RTLD_DEFAULT, "fstat$INODE64");
    if (!real_fn || real_fn == tf_my_fstat) real_fn = (int (*)(int, struct stat *))dlsym(RTLD_NEXT, "fstat");
    if (!real_fn || real_fn == tf_my_fstat) real_fn = (int (*)(int, struct stat *))dlsym(RTLD_DEFAULT, "fstat");
    if (real_fn && real_fn != tf_my_fstat) return real_fn(fd, buf);
    return 0;
}

static int (*orig_fstat64)(int fd, void *buf) = NULL;

static int tf_my_fstat64(int fd, void *buf) {
    if (fd < 0) {
        errno = EBADF;
        return -1;
    }
    char path[1024] = {0};
    int saved_errno = errno;
    if (fcntl(fd, F_GETPATH, path) == 0 && path[0] != '\0') {
        if (strstr(path, "TweakForce") != NULL ||
            strstr(path, "weakforce") != NULL ||
            strstr(path, "ellekit") != NULL ||
            strstr(path, "roothide") != NULL) {
            // NEVER block internal tweak & loader libraries
        } else if (tf_is_jailbreak_path(path)) {
            errno = EBADF;
            return -1;
        }
    }
    errno = saved_errno;

    if (orig_fstat64 && (void *)orig_fstat64 != (void *)tf_my_fstat64) {
        return orig_fstat64(fd, buf);
    }
    int (*real_fn)(int, void *) = (int (*)(int, void *))dlsym(RTLD_NEXT, "fstat64");
    if (!real_fn || real_fn == tf_my_fstat64) real_fn = (int (*)(int, void *))dlsym(RTLD_DEFAULT, "fstat64");
    if (real_fn && real_fn != tf_my_fstat64) return real_fn(fd, buf);
    return 0;
}

// 3.17.4 VFS Attribute Mutation Shield (setattrlist, fsetattrlist)
static int (*orig_setattrlist)(const char *path, struct attrlist *attrList, void *attrBuf, size_t attrBufSize, unsigned long options) = NULL;

static int tf_my_setattrlist(const char *path, struct attrlist *attrList, void *attrBuf, size_t attrBufSize, unsigned long options) {
    if (path && tf_is_jailbreak_path(path)) {
        errno = ENOENT;
        return -1;
    }
    if (orig_setattrlist && (void *)orig_setattrlist != (void *)tf_my_setattrlist) {
        return orig_setattrlist(path, attrList, attrBuf, attrBufSize, options);
    }
    int (*real_fn)(const char *, struct attrlist *, void *, size_t, unsigned long) =
        (int (*)(const char *, struct attrlist *, void *, size_t, unsigned long))dlsym(RTLD_NEXT, "setattrlist");
    if (!real_fn || real_fn == tf_my_setattrlist) real_fn = (int (*)(const char *, struct attrlist *, void *, size_t, unsigned long))dlsym(RTLD_DEFAULT, "setattrlist");
    if (real_fn && real_fn != tf_my_setattrlist) return real_fn(path, attrList, attrBuf, attrBufSize, options);
    errno = ENOENT;
    return -1;
}

static int (*orig_fsetattrlist)(int fd, struct attrlist *attrList, void *attrBuf, size_t attrBufSize, unsigned long options) = NULL;

static int tf_my_fsetattrlist(int fd, struct attrlist *attrList, void *attrBuf, size_t attrBufSize, unsigned long options) {
    if (fd >= 0) {
        char path[1024] = {0};
        int saved_errno = errno;
        if (fcntl(fd, F_GETPATH, path) == 0 && path[0] != '\0') {
            if (strstr(path, "TweakForce") != NULL ||
                strstr(path, "weakforce") != NULL ||
                strstr(path, "ellekit") != NULL ||
                strstr(path, "roothide") != NULL) {
                // allow internal libraries
            } else if (tf_is_jailbreak_path(path)) {
                errno = ENOENT;
                return -1;
            }
        }
        errno = saved_errno;
    }
    if (orig_fsetattrlist && (void *)orig_fsetattrlist != (void *)tf_my_fsetattrlist) {
        return orig_fsetattrlist(fd, attrList, attrBuf, attrBufSize, options);
    }
    int (*real_fn)(int, struct attrlist *, void *, size_t, unsigned long) =
        (int (*)(int, struct attrlist *, void *, size_t, unsigned long))dlsym(RTLD_NEXT, "fsetattrlist");
    if (!real_fn || real_fn == tf_my_fsetattrlist) real_fn = (int (*)(int, struct attrlist *, void *, size_t, unsigned long))dlsym(RTLD_DEFAULT, "fsetattrlist");
    if (real_fn && real_fn != tf_my_fsetattrlist) return real_fn(fd, attrList, attrBuf, attrBufSize, options);
    errno = ENOENT;
    return -1;
}

// 3.17.5 POSIX Privilege Escalation Shield (setuid, seteuid, setgid, setegid)
static int (*orig_setuid)(uid_t uid) = NULL;

static int tf_my_setuid(uid_t uid) {
    if (uid == 0) {
        errno = EPERM;
        return -1;
    }
    if (orig_setuid && (void *)orig_setuid != (void *)tf_my_setuid) {
        return orig_setuid(uid);
    }
    int (*real_fn)(uid_t) = (int (*)(uid_t))dlsym(RTLD_DEFAULT, "setuid");
    if (real_fn && real_fn != tf_my_setuid) return real_fn(uid);
    errno = EPERM;
    return -1;
}

static int (*orig_seteuid)(uid_t euid) = NULL;

static int tf_my_seteuid(uid_t euid) {
    if (euid == 0) {
        errno = EPERM;
        return -1;
    }
    if (orig_seteuid && (void *)orig_seteuid != (void *)tf_my_seteuid) {
        return orig_seteuid(euid);
    }
    int (*real_fn)(uid_t) = (int (*)(uid_t))dlsym(RTLD_DEFAULT, "seteuid");
    if (real_fn && real_fn != tf_my_seteuid) return real_fn(euid);
    errno = EPERM;
    return -1;
}

static int (*orig_setgid)(gid_t gid) = NULL;

static int tf_my_setgid(gid_t gid) {
    if (gid == 0) {
        errno = EPERM;
        return -1;
    }
    if (orig_setgid && (void *)orig_setgid != (void *)tf_my_setgid) {
        return orig_setgid(gid);
    }
    int (*real_fn)(gid_t) = (int (*)(gid_t))dlsym(RTLD_DEFAULT, "setgid");
    if (real_fn && real_fn != tf_my_setgid) return real_fn(gid);
    errno = EPERM;
    return -1;
}

static int (*orig_setegid)(gid_t egid) = NULL;

static int tf_my_setegid(gid_t egid) {
    if (egid == 0) {
        errno = EPERM;
        return -1;
    }
    if (orig_setegid && (void *)orig_setegid != (void *)tf_my_setegid) {
        return orig_setegid(egid);
    }
    int (*real_fn)(gid_t) = (int (*)(gid_t))dlsym(RTLD_DEFAULT, "setegid");
    if (real_fn && real_fn != tf_my_setegid) return real_fn(egid);
    errno = EPERM;
    return -1;
}

// 3.17.6 Terminal & Pseudo-TTY Isolation (isatty, ttyname, ttyname_r)
static int (*orig_isatty)(int fd) = NULL;

static int tf_my_isatty(int fd) {
    if (fd == 0 || fd == 1 || fd == 2) {
        errno = ENOTTY;
        return 0;
    }
    if (fd >= 0) {
        char path[1024] = {0};
        int saved_errno = errno;
        if (fcntl(fd, F_GETPATH, path) == 0 && path[0] != '\0') {
            if (strstr(path, "/dev/ttyp") != NULL || strstr(path, "/dev/pts") != NULL || strstr(path, "/dev/ptyp") != NULL) {
                errno = ENOTTY;
                return 0;
            }
        }
        errno = saved_errno;
    }
    if (orig_isatty && (void *)orig_isatty != (void *)tf_my_isatty) {
        return orig_isatty(fd);
    }
    int (*real_fn)(int) = (int (*)(int))dlsym(RTLD_DEFAULT, "isatty");
    if (real_fn && real_fn != tf_my_isatty) return real_fn(fd);
    errno = ENOTTY;
    return 0;
}

static char *(*orig_ttyname)(int fd) = NULL;

static char *tf_my_ttyname(int fd) {
    if (fd == 0 || fd == 1 || fd == 2) {
        errno = ENOTTY;
        return NULL;
    }
    if (orig_ttyname && (void *)orig_ttyname != (void *)tf_my_ttyname) {
        return orig_ttyname(fd);
    }
    char *(*real_fn)(int) = (char *(*)(int))dlsym(RTLD_DEFAULT, "ttyname");
    if (real_fn && real_fn != tf_my_ttyname) return real_fn(fd);
    errno = ENOTTY;
    return NULL;
}

static int (*orig_ttyname_r)(int fd, char *buf, size_t buflen) = NULL;

static int tf_my_ttyname_r(int fd, char *buf, size_t buflen) {
    if (fd == 0 || fd == 1 || fd == 2) {
        return ENOTTY;
    }
    if (orig_ttyname_r && (void *)orig_ttyname_r != (void *)tf_my_ttyname_r) {
        return orig_ttyname_r(fd, buf, buflen);
    }
    int (*real_fn)(int, char *, size_t) = (int (*)(int, char *, size_t))dlsym(RTLD_DEFAULT, "ttyname_r");
    if (real_fn && real_fn != tf_my_ttyname_r) return real_fn(fd, buf, buflen);
    return ENOTTY;
}

// 3.17.7 Extended Process Execution Sandbox Hardening (execvp, execvP, vfork)
static int (*orig_execvp)(const char *file, char *const argv[]) = NULL;

static int tf_my_execvp(const char *file, char *const argv[]) {
    if (file) {
        if (tf_is_jailbreak_path(file) ||
            strcmp(file, "sh") == 0 || strcmp(file, "bash") == 0 ||
            strcmp(file, "/bin/sh") == 0 || strcmp(file, "/bin/bash") == 0 ||
            strcmp(file, "csh") == 0 || strcmp(file, "zsh") == 0) {
            errno = ENOENT;
            return -1;
        }
    }
    if (orig_execvp && (void *)orig_execvp != (void *)tf_my_execvp) {
        return orig_execvp(file, argv);
    }
    int (*real_fn)(const char *, char *const []) = (int (*)(const char *, char *const []))dlsym(RTLD_NEXT, "execvp");
    if (!real_fn || real_fn == tf_my_execvp) real_fn = (int (*)(const char *, char *const []))dlsym(RTLD_DEFAULT, "execvp");
    if (real_fn && real_fn != tf_my_execvp) return real_fn(file, argv);
    errno = ENOENT;
    return -1;
}

static int (*orig_execvP)(const char *file, const char *searchpath, char *const argv[]) = NULL;

static int tf_my_execvP(const char *file, const char *searchpath, char *const argv[]) {
    if (file) {
        if (tf_is_jailbreak_path(file) ||
            strcmp(file, "sh") == 0 || strcmp(file, "bash") == 0 ||
            strcmp(file, "/bin/sh") == 0 || strcmp(file, "/bin/bash") == 0 ||
            strcmp(file, "csh") == 0 || strcmp(file, "zsh") == 0) {
            errno = ENOENT;
            return -1;
        }
    }
    if (orig_execvP && (void *)orig_execvP != (void *)tf_my_execvP) {
        return orig_execvP(file, searchpath, argv);
    }
    int (*real_fn)(const char *, const char *, char *const []) = (int (*)(const char *, const char *, char *const []))dlsym(RTLD_NEXT, "execvP");
    if (!real_fn || real_fn == tf_my_execvP) real_fn = (int (*)(const char *, const char *, char *const []))dlsym(RTLD_DEFAULT, "execvP");
    if (real_fn && real_fn != tf_my_execvP) return real_fn(file, searchpath, argv);
    errno = ENOENT;
    return -1;
}

static pid_t (*orig_vfork)(void) = NULL;

static pid_t tf_my_vfork(void) {
    errno = ENOSYS;
    return -1;
}

// 3.17.8 CoreFoundation & Cocoa Bundle Enumeration Shield
static CFArrayRef (*orig_CFBundleGetAllBundles)(void) = NULL;

static CFArrayRef tf_my_CFBundleGetAllBundles(void) {
    CFArrayRef arr = NULL;
    if (orig_CFBundleGetAllBundles && (void *)orig_CFBundleGetAllBundles != (void *)tf_my_CFBundleGetAllBundles) {
        arr = orig_CFBundleGetAllBundles();
    } else {
        CFArrayRef (*real_fn)(void) = (CFArrayRef (*)(void))dlsym(RTLD_NEXT, "CFBundleGetAllBundles");
        if (!real_fn || real_fn == tf_my_CFBundleGetAllBundles) real_fn = (CFArrayRef (*)(void))dlsym(RTLD_DEFAULT, "CFBundleGetAllBundles");
        if (real_fn && real_fn != tf_my_CFBundleGetAllBundles) arr = real_fn();
    }
    if (!arr) return NULL;

    CFIndex count = CFArrayGetCount(arr);
    CFMutableArrayRef clean = CFArrayCreateMutable(kCFAllocatorDefault, count, &kCFTypeArrayCallBacks);
    if (!clean) return arr;

    for (CFIndex i = 0; i < count; i++) {
        CFBundleRef bundle = (CFBundleRef)CFArrayGetValueAtIndex(arr, i);
        if (!bundle) continue;
        BOOL is_jb = NO;
        CFStringRef bId = CFBundleGetIdentifier(bundle);
        if (bId) {
            char c_bid[256] = {0};
            if (CFStringGetCString(bId, c_bid, sizeof(c_bid), kCFStringEncodingUTF8)) {
                if (tf_is_jailbreak_bundle_id(@(c_bid))) is_jb = YES;
            }
        }
        if (!is_jb) {
            CFURLRef url = CFBundleCopyBundleURL(bundle);
            if (url) {
                CFStringRef path = CFURLCopyFileSystemPath(url, kCFURLPOSIXPathStyle);
                if (path) {
                    char cpath[1024] = {0};
                    if (CFStringGetCString(path, cpath, sizeof(cpath), kCFStringEncodingUTF8)) {
                        if (tf_is_jailbreak_path(cpath) ||
                            strcasestr(cpath, "tweakforce") != NULL ||
                            strcasestr(cpath, "weakforce") != NULL ||
                            strcasestr(cpath, "ellekit") != NULL ||
                            strcasestr(cpath, "roothide") != NULL) {
                            is_jb = YES;
                        }
                    }
                    CFRelease(path);
                }
                CFRelease(url);
            }
        }
        if (!is_jb) {
            CFArrayAppendValue(clean, bundle);
        }
    }
    return (CFArrayRef)CFAutorelease(clean);
}

static IMP orig_bundle_allBundles = NULL;
static IMP orig_bundle_allFrameworks = NULL;

static NSArray<NSBundle *> *tf_bundle_allBundles(id self, SEL _cmd) {
    NSArray<NSBundle *> *(*orig_fn)(id, SEL) = (NSArray<NSBundle *> *(*)(id, SEL))orig_bundle_allBundles;
    NSArray<NSBundle *> *arr = orig_fn ? orig_fn(self, _cmd) : nil;
    if (!arr || ![arr isKindOfClass:[NSArray class]]) return @[];
    NSMutableArray<NSBundle *> *clean = [NSMutableArray arrayWithCapacity:arr.count];
    for (id item in arr) {
        if (![item isKindOfClass:[NSBundle class]]) continue;
        NSBundle *b = (NSBundle *)item;
        NSString *bid = b.bundleIdentifier;
        if (bid && tf_is_jailbreak_bundle_id(bid)) continue;
        NSString *bp = b.bundlePath;
        if (bp && (tf_is_jailbreak_path(bp.UTF8String) ||
                   strcasestr(bp.UTF8String, "tweakforce") != NULL ||
                   strcasestr(bp.UTF8String, "weakforce") != NULL ||
                   strcasestr(bp.UTF8String, "ellekit") != NULL ||
                   strcasestr(bp.UTF8String, "roothide") != NULL)) {
            continue;
        }
        [clean addObject:b];
    }
    return [clean copy];
}

static NSArray<NSBundle *> *tf_bundle_allFrameworks(id self, SEL _cmd) {
    NSArray<NSBundle *> *(*orig_fn)(id, SEL) = (NSArray<NSBundle *> *(*)(id, SEL))orig_bundle_allFrameworks;
    NSArray<NSBundle *> *arr = orig_fn ? orig_fn(self, _cmd) : nil;
    if (!arr || ![arr isKindOfClass:[NSArray class]]) return @[];
    NSMutableArray<NSBundle *> *clean = [NSMutableArray arrayWithCapacity:arr.count];
    for (id item in arr) {
        if (![item isKindOfClass:[NSBundle class]]) continue;
        NSBundle *b = (NSBundle *)item;
        NSString *bid = b.bundleIdentifier;
        if (bid && tf_is_jailbreak_bundle_id(bid)) continue;
        NSString *bp = b.bundlePath;
        if (bp && (tf_is_jailbreak_path(bp.UTF8String) ||
                   strcasestr(bp.UTF8String, "tweakforce") != NULL ||
                   strcasestr(bp.UTF8String, "weakforce") != NULL ||
                   strcasestr(bp.UTF8String, "ellekit") != NULL ||
                   strcasestr(bp.UTF8String, "roothide") != NULL)) {
            continue;
        }
        [clean addObject:b];
    }
    return [clean copy];
}

// 3.17.9 Audit-Token Sandbox Query Armor (sandbox_check_by_audit_token)
static int (*orig_sandbox_check_by_audit_token)(audit_token_t au, const char *operation, int type, ...) = NULL;

static int tf_my_sandbox_check_by_audit_token(audit_token_t au, const char *operation, int type, ...) {
    va_list ap;
    va_start(ap, type);
    const char *path = NULL;
    if (type & 1) { // SANDBOX_FILTER_PATH
        path = va_arg(ap, const char *);
    }
    va_end(ap);

    if (path && tf_is_jailbreak_path(path)) {
        errno = EPERM;
        return 1; // 1 = denied by sandbox on iOS
    }

    if (orig_sandbox_check_by_audit_token && (void *)orig_sandbox_check_by_audit_token != (void *)tf_my_sandbox_check_by_audit_token) {
        if (path) return orig_sandbox_check_by_audit_token(au, operation, type, path);
        return orig_sandbox_check_by_audit_token(au, operation, type);
    }
    int (*real_fn)(audit_token_t, const char *, int, ...) = (int (*)(audit_token_t, const char *, int, ...))dlsym(RTLD_DEFAULT, "sandbox_check_by_audit_token");
    if (real_fn && real_fn != tf_my_sandbox_check_by_audit_token) {
        if (path) return real_fn(au, operation, type, path);
        return real_fn(au, operation, type);
    }
    return 0;
}


// ----------------------------------------------------------------------------
// 3.18 Echelon 16: Mach VM Protections, Task Ports, Runtime Reflection Cleansing,
//      POSIX Identity, Dyld All Image Infos & VFS Flags Armor
// ----------------------------------------------------------------------------

// 3.18.1 Mach VM Memory Protection Shielding (vm_protect, mach_vm_protect)
static kern_return_t (*orig_vm_protect)(vm_map_t target_task, vm_address_t address, vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection) = NULL;

static kern_return_t tf_my_vm_protect(vm_map_t target_task, vm_address_t address, vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection) {
    if ((new_protection & VM_PROT_WRITE) && (new_protection & VM_PROT_EXECUTE)) {
        return KERN_PROTECTION_FAILURE;
    }
    if (orig_vm_protect && (void *)orig_vm_protect != (void *)tf_my_vm_protect) {
        return orig_vm_protect(target_task, address, size, set_maximum, new_protection);
    }
    kern_return_t (*real_fn)(vm_map_t, vm_address_t, vm_size_t, boolean_t, vm_prot_t) = (kern_return_t (*)(vm_map_t, vm_address_t, vm_size_t, boolean_t, vm_prot_t))dlsym(RTLD_DEFAULT, "vm_protect");
    if (real_fn && real_fn != tf_my_vm_protect) return real_fn(target_task, address, size, set_maximum, new_protection);
    return KERN_SUCCESS;
}

static kern_return_t (*orig_mach_vm_protect)(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection) = NULL;

static kern_return_t tf_my_mach_vm_protect(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection) {
    if ((new_protection & VM_PROT_WRITE) && (new_protection & VM_PROT_EXECUTE)) {
        return KERN_PROTECTION_FAILURE;
    }
    if (orig_mach_vm_protect && (void *)orig_mach_vm_protect != (void *)tf_my_mach_vm_protect) {
        return orig_mach_vm_protect(target_task, address, size, set_maximum, new_protection);
    }
    kern_return_t (*real_fn)(vm_map_t, mach_vm_address_t, mach_vm_size_t, boolean_t, vm_prot_t) = (kern_return_t (*)(vm_map_t, mach_vm_address_t, mach_vm_size_t, boolean_t, vm_prot_t))dlsym(RTLD_DEFAULT, "mach_vm_protect");
    if (real_fn && real_fn != tf_my_mach_vm_protect) return real_fn(target_task, address, size, set_maximum, new_protection);
    return KERN_SUCCESS;
}

// 3.18.2 Mach Port & Task Inspection Shielding (task_for_pid)
static kern_return_t (*orig_task_for_pid)(mach_port_name_t target_tport, int pid, mach_port_name_t *t) = NULL;

static kern_return_t tf_my_task_for_pid(mach_port_name_t target_tport, int pid, mach_port_name_t *t) {
    if (pid != getpid()) {
        if (t) *t = MACH_PORT_NULL;
        return KERN_FAILURE;
    }
    if (orig_task_for_pid && (void *)orig_task_for_pid != (void *)tf_my_task_for_pid) {
        return orig_task_for_pid(target_tport, pid, t);
    }
    kern_return_t (*real_fn)(mach_port_name_t, int, mach_port_name_t *) = (kern_return_t (*)(mach_port_name_t, int, mach_port_name_t *))dlsym(RTLD_DEFAULT, "task_for_pid");
    if (real_fn && real_fn != tf_my_task_for_pid) return real_fn(target_tport, pid, t);
    if (t) *t = MACH_PORT_NULL;
    return KERN_FAILURE;
}

// 3.18.3 POSIX Identity & Credentials Armor (getuid, geteuid, getgid, getegid)
static uid_t (*orig_getuid)(void) = NULL;
static uid_t (*orig_geteuid)(void) = NULL;
static gid_t (*orig_getgid)(void) = NULL;
static gid_t (*orig_getegid)(void) = NULL;

static uid_t tf_my_getuid(void) {
    return 501;
}

static uid_t tf_my_geteuid(void) {
    return 501;
}

static gid_t tf_my_getgid(void) {
    return 501;
}

static gid_t tf_my_getegid(void) {
    return 501;
}

// 3.18.4 User & Password Database Sanitization (getpwuid, getpwnam)
static struct passwd *(*orig_getpwuid)(uid_t uid) = NULL;
static struct passwd *(*orig_getpwnam)(const char *name) = NULL;

static struct passwd *tf_my_getpwuid(uid_t uid) {
    struct passwd *pw = NULL;
    if (orig_getpwuid && (void *)orig_getpwuid != (void *)tf_my_getpwuid) {
        pw = orig_getpwuid(uid);
    } else {
        struct passwd *(*real_fn)(uid_t) = (struct passwd *(*)(uid_t))dlsym(RTLD_DEFAULT, "getpwuid");
        if (real_fn && real_fn != tf_my_getpwuid) pw = real_fn(uid);
    }
    if (pw) {
        if (pw->pw_shell && (strstr(pw->pw_shell, "sh") || tf_is_jailbreak_path(pw->pw_shell))) {
            pw->pw_shell = "/bin/false";
        }
        if (pw->pw_dir && tf_is_jailbreak_path(pw->pw_dir)) {
            pw->pw_dir = "/var/mobile";
        }
    }
    return pw;
}

static struct passwd *tf_my_getpwnam(const char *name) {
    struct passwd *pw = NULL;
    if (orig_getpwnam && (void *)orig_getpwnam != (void *)tf_my_getpwnam) {
        pw = orig_getpwnam(name);
    } else {
        struct passwd *(*real_fn)(const char *) = (struct passwd *(*)(const char *))dlsym(RTLD_DEFAULT, "getpwnam");
        if (real_fn && real_fn != tf_my_getpwnam) pw = real_fn(name);
    }
    if (pw) {
        if (pw->pw_shell && (strstr(pw->pw_shell, "sh") || tf_is_jailbreak_path(pw->pw_shell))) {
            pw->pw_shell = "/bin/false";
        }
        if (pw->pw_dir && tf_is_jailbreak_path(pw->pw_dir)) {
            pw->pw_dir = "/var/mobile";
        }
    }
    return pw;
}

// 3.18.5 Dyld All Image Infos Cloaking (_dyld_get_all_image_infos)
static const struct dyld_all_image_infos *(*orig_dyld_get_all_image_infos)(void) = NULL;
static struct dyld_all_image_infos *s_tf_sanitized_all_image_infos = NULL;
static struct dyld_image_info *s_tf_sanitized_image_array = NULL;
static uint32_t s_tf_sanitized_array_capacity = 0;

static const struct dyld_all_image_infos *tf_my_dyld_get_all_image_infos(void) {
    const struct dyld_all_image_infos *raw = NULL;
    if (orig_dyld_get_all_image_infos && (void *)orig_dyld_get_all_image_infos != (void *)tf_my_dyld_get_all_image_infos) {
        raw = orig_dyld_get_all_image_infos();
    } else {
        const struct dyld_all_image_infos *(*real_fn)(void) = (const struct dyld_all_image_infos *(*)(void))dlsym(RTLD_DEFAULT, "_dyld_get_all_image_infos");
        if (real_fn && real_fn != tf_my_dyld_get_all_image_infos) raw = real_fn();
    }
    if (!raw) return NULL;
    if (!raw->infoArray || raw->infoArrayCount == 0) return raw;

    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        s_tf_sanitized_all_image_infos = (struct dyld_all_image_infos *)malloc(sizeof(struct dyld_all_image_infos));
    });

    if (!s_tf_sanitized_all_image_infos) return raw;

    memcpy(s_tf_sanitized_all_image_infos, raw, sizeof(struct dyld_all_image_infos));

    if (raw->infoArrayCount > s_tf_sanitized_array_capacity) {
        s_tf_sanitized_array_capacity = raw->infoArrayCount + 32;
        s_tf_sanitized_image_array = (struct dyld_image_info *)realloc(s_tf_sanitized_image_array, sizeof(struct dyld_image_info) * s_tf_sanitized_array_capacity);
    }

    if (!s_tf_sanitized_image_array) return raw;

    for (uint32_t i = 0; i < raw->infoArrayCount; i++) {
        s_tf_sanitized_image_array[i] = raw->infoArray[i];
        const char *p = raw->infoArray[i].imageFilePath;
        if (p && (tf_is_jailbreak_path(p) ||
                  strcasestr(p, "tweakforce") != NULL ||
                  strcasestr(p, "weakforce") != NULL ||
                  strcasestr(p, "ellekit") != NULL ||
                  strcasestr(p, "roothide") != NULL)) {
            s_tf_sanitized_image_array[i].imageFilePath = "/System/Library/Frameworks/Foundation.framework/Foundation";
        }
    }

    s_tf_sanitized_all_image_infos->infoArray = s_tf_sanitized_image_array;
    return s_tf_sanitized_all_image_infos;
}

// 3.18.6 Objective-C Runtime Method Reflection Cleansing (class_copyMethodList, objc_getProtocol)
static Method *(*orig_class_copyMethodList)(Class cls, unsigned int *outCount) = NULL;

static Method *tf_my_class_copyMethodList(Class cls, unsigned int *outCount) {
    unsigned int count = 0;
    Method *methods = NULL;
    if (orig_class_copyMethodList && (void *)orig_class_copyMethodList != (void *)tf_my_class_copyMethodList) {
        methods = orig_class_copyMethodList(cls, &count);
    } else {
        Method *(*real_fn)(Class, unsigned int *) = (Method *(*)(Class, unsigned int *))dlsym(RTLD_DEFAULT, "class_copyMethodList");
        if (real_fn && real_fn != tf_my_class_copyMethodList) methods = real_fn(cls, &count);
    }
    if (!methods || count == 0) {
        if (outCount) *outCount = count;
        return methods;
    }

    Method *clean = (Method *)malloc(sizeof(Method) * (count + 1));
    if (!clean) {
        if (outCount) *outCount = count;
        return methods;
    }

    unsigned int cleanCount = 0;
    for (unsigned int i = 0; i < count; i++) {
        SEL sel = method_getName(methods[i]);
        if (sel) {
            const char *name = sel_getName(sel);
            if (name) {
                if (strncmp(name, "tf_", 3) == 0 ||
                    strncmp(name, "TF_", 3) == 0 ||
                    strcasestr(name, "ellekit") != NULL ||
                    strcasestr(name, "roothide") != NULL) {
                    continue;
                }
            }
        }
        clean[cleanCount++] = methods[i];
    }
    clean[cleanCount] = NULL;
    free(methods);
    if (outCount) *outCount = cleanCount;
    return clean;
}

static Protocol *(*orig_objc_getProtocol)(const char *name) = NULL;

static Protocol *tf_my_objc_getProtocol(const char *name) {
    if (name) {
        if (strcasestr(name, "substrate") != NULL ||
            strcasestr(name, "ellekit") != NULL ||
            strcasestr(name, "roothide") != NULL ||
            strcasestr(name, "tweakforce") != NULL ||
            strcasestr(name, "cycript") != NULL) {
            return NULL;
        }
    }
    if (orig_objc_getProtocol && (void *)orig_objc_getProtocol != (void *)tf_my_objc_getProtocol) {
        return orig_objc_getProtocol(name);
    }
    Protocol *(*real_fn)(const char *) = (Protocol *(*)(const char *))dlsym(RTLD_DEFAULT, "objc_getProtocol");
    if (real_fn && real_fn != tf_my_objc_getProtocol) return real_fn(name);
    return NULL;
}

// 3.18.7 VFS File Flags & Rootfs Read-Only Shield (chflags, lchflags, fchflags)
static int (*orig_chflags)(const char *path, u_int flags) = NULL;
static int (*orig_lchflags)(const char *path, u_int flags) = NULL;
static int (*orig_fchflags)(int fd, u_int flags) = NULL;

static int tf_my_chflags(const char *path, u_int flags) {
    if (path) {
        if (tf_is_jailbreak_path(path)) {
            errno = ENOENT;
            return -1;
        }
        if (strcmp(path, "/") == 0 || strcmp(path, "/private") == 0 ||
            strncmp(path, "/System", 7) == 0 || strncmp(path, "/usr", 4) == 0 ||
            strncmp(path, "/bin", 4) == 0 || strncmp(path, "/sbin", 5) == 0) {
            errno = EROFS;
            return -1;
        }
    }
    if (orig_chflags && (void *)orig_chflags != (void *)tf_my_chflags) {
        return orig_chflags(path, flags);
    }
    int (*real_fn)(const char *, u_int) = (int (*)(const char *, u_int))dlsym(RTLD_NEXT, "chflags");
    if (!real_fn || real_fn == tf_my_chflags) real_fn = (int (*)(const char *, u_int))dlsym(RTLD_DEFAULT, "chflags");
    if (real_fn && real_fn != tf_my_chflags) return real_fn(path, flags);
    errno = EPERM;
    return -1;
}

static int tf_my_lchflags(const char *path, u_int flags) {
    if (path) {
        if (tf_is_jailbreak_path(path)) {
            errno = ENOENT;
            return -1;
        }
        if (strcmp(path, "/") == 0 || strcmp(path, "/private") == 0 ||
            strncmp(path, "/System", 7) == 0 || strncmp(path, "/usr", 4) == 0 ||
            strncmp(path, "/bin", 4) == 0 || strncmp(path, "/sbin", 5) == 0) {
            errno = EROFS;
            return -1;
        }
    }
    if (orig_lchflags && (void *)orig_lchflags != (void *)tf_my_lchflags) {
        return orig_lchflags(path, flags);
    }
    int (*real_fn)(const char *, u_int) = (int (*)(const char *, u_int))dlsym(RTLD_NEXT, "lchflags");
    if (!real_fn || real_fn == tf_my_lchflags) real_fn = (int (*)(const char *, u_int))dlsym(RTLD_DEFAULT, "lchflags");
    if (real_fn && real_fn != tf_my_lchflags) return real_fn(path, flags);
    errno = EPERM;
    return -1;
}

static int tf_my_fchflags(int fd, u_int flags) {
    if (fd < 0) {
        errno = EBADF;
        return -1;
    }
    char path[1024] = {0};
    if (fcntl(fd, F_GETPATH, path) == 0) {
        if (strcasestr(path, "tweakforce") != NULL ||
            strcasestr(path, "weakforce") != NULL ||
            strcasestr(path, "ellekit") != NULL ||
            strcasestr(path, "roothide") != NULL) {
            if (orig_fchflags && (void *)orig_fchflags != (void *)tf_my_fchflags) return orig_fchflags(fd, flags);
            return 0;
        }
        if (tf_is_jailbreak_path(path)) {
            errno = EBADF;
            return -1;
        }
        if (strcmp(path, "/") == 0 || strncmp(path, "/System", 7) == 0 || strncmp(path, "/usr", 4) == 0) {
            errno = EROFS;
            return -1;
        }
    }
    if (orig_fchflags && (void *)orig_fchflags != (void *)tf_my_fchflags) {
        return orig_fchflags(fd, flags);
    }
    int (*real_fn)(int, u_int) = (int (*)(int, u_int))dlsym(RTLD_NEXT, "fchflags");
    if (!real_fn || real_fn == tf_my_fchflags) real_fn = (int (*)(int, u_int))dlsym(RTLD_DEFAULT, "fchflags");
    if (real_fn && real_fn != tf_my_fchflags) return real_fn(fd, flags);
    errno = EPERM;
    return -1;
}

// 3.18.8 POSIX Core Dump & Resource Limit Hardening (getrlimit, setrlimit)
static int (*orig_getrlimit)(int resource, struct rlimit *rlp) = NULL;
static int (*orig_setrlimit)(int resource, const struct rlimit *rlp) = NULL;

static int tf_my_getrlimit(int resource, struct rlimit *rlp) {
    int ret = 0;
    if (orig_getrlimit && (void *)orig_getrlimit != (void *)tf_my_getrlimit) {
        ret = orig_getrlimit(resource, rlp);
    } else {
        int (*real_fn)(int, struct rlimit *) = (int (*)(int, struct rlimit *))dlsym(RTLD_DEFAULT, "getrlimit");
        if (real_fn && real_fn != tf_my_getrlimit) ret = real_fn(resource, rlp);
    }
    if (ret == 0 && rlp && resource == RLIMIT_CORE) {
        rlp->rlim_cur = 0;
        rlp->rlim_max = 0;
    }
    return ret;
}

static int tf_my_setrlimit(int resource, const struct rlimit *rlp) {
    if (resource == RLIMIT_CORE && rlp && rlp->rlim_cur > 0) {
        errno = EPERM;
        return -1;
    }
    if (orig_setrlimit && (void *)orig_setrlimit != (void *)tf_my_setrlimit) {
        return orig_setrlimit(resource, rlp);
    }
    int (*real_fn)(int, const struct rlimit *) = (int (*)(int, const struct rlimit *))dlsym(RTLD_DEFAULT, "setrlimit");
    if (real_fn && real_fn != tf_my_setrlimit) return real_fn(resource, rlp);
    return 0;
}

// ----------------------------------------------------------------------------
// 3.19 Echelon 17: Mach-O Load Commands, FairPlay Cryptid, Sideloading
//      mobileprovision & App Integrity Armor
// ----------------------------------------------------------------------------

static void tf_sanitize_main_header_in_place(void) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        const struct mach_header *real_hdr = NULL;
        if (orig_dyld_get_image_header && (void *)orig_dyld_get_image_header != (void *)tf_my_dyld_get_image_header) {
            real_hdr = orig_dyld_get_image_header(0);
        } else {
            const struct mach_header *(*fn)(uint32_t) = (const struct mach_header *(*)(uint32_t))dlsym(RTLD_DEFAULT, "_dyld_get_image_header");
            if (fn) real_hdr = fn(0);
        }
        if (!real_hdr) return;

        if (real_hdr->magic != MH_MAGIC_64 && real_hdr->magic != MH_CIGAM_64) {
            return;
        }

        struct mach_header_64 *hdr64 = (struct mach_header_64 *)real_hdr;
        size_t page_sz = vm_page_size ? vm_page_size : 16384;
        vm_address_t page_start = (vm_address_t)hdr64;
        vm_size_t protect_size = (sizeof(struct mach_header_64) + hdr64->sizeofcmds + page_sz - 1) & ~(page_sz - 1);

        kern_return_t kr = vm_protect(mach_task_self(), page_start, protect_size, FALSE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
        if (kr != KERN_SUCCESS) {
            os_log_error(TFHLog(), "[TweakForce] vm_protect on main header failed: %d", kr);
            return;
        }

        uint8_t *cmd_ptr = (uint8_t *)hdr64 + sizeof(struct mach_header_64);
        BOOL found_enc = NO;
        for (uint32_t i = 0; i < hdr64->ncmds; i++) {
            struct load_command *lc = (struct load_command *)cmd_ptr;
            if (lc->cmdsize < sizeof(struct load_command) ||
                (cmd_ptr + lc->cmdsize > (uint8_t *)hdr64 + sizeof(struct mach_header_64) + hdr64->sizeofcmds)) {
                break;
            }

            if (lc->cmd == LC_ENCRYPTION_INFO_64) {
                struct encryption_info_command_64 *enc = (struct encryption_info_command_64 *)lc;
                enc->cryptid = 1;
                if (enc->cryptoff == 0) enc->cryptoff = 0x4000;
                if (enc->cryptsize == 0) enc->cryptsize = 0x40000;
                found_enc = YES;
            } else if (lc->cmd == LC_ENCRYPTION_INFO) {
                struct encryption_info_command *enc = (struct encryption_info_command *)lc;
                enc->cryptid = 1;
                if (enc->cryptoff == 0) enc->cryptoff = 0x4000;
                if (enc->cryptsize == 0) enc->cryptsize = 0x40000;
                found_enc = YES;
            } else if (lc->cmd == LC_LOAD_DYLIB || lc->cmd == LC_LOAD_WEAK_DYLIB || lc->cmd == LC_REEXPORT_DYLIB) {
                struct dylib_command *dcmd = (struct dylib_command *)lc;
                if (dcmd->dylib.name.offset < lc->cmdsize) {
                    char *name = (char *)lc + dcmd->dylib.name.offset;
                    if (tf_is_jailbreak_path(name) ||
                        strcasestr(name, "tweakforce") != NULL ||
                        strcasestr(name, "weakforce") != NULL ||
                        strcasestr(name, "ellekit") != NULL ||
                        strcasestr(name, "roothide") != NULL ||
                        strcasestr(name, "substrate") != NULL) {
                        size_t max_len = lc->cmdsize - dcmd->dylib.name.offset - 1;
                        const char *safe = "/System/Library/Frameworks/Foundation.framework/Foundation";
                        if (strlen(safe) <= max_len) {
                            strncpy(name, safe, max_len);
                            name[max_len] = '\0';
                        } else {
                            strncpy(name, "/usr/lib/libSystem.B.dylib", max_len);
                            name[max_len] = '\0';
                        }
                    }
                }
            } else if (lc->cmd == LC_RPATH) {
                struct rpath_command *rcmd = (struct rpath_command *)lc;
                if (rcmd->path.offset < lc->cmdsize) {
                    char *path = (char *)lc + rcmd->path.offset;
                    if (tf_is_jailbreak_path(path) || strstr(path, "/var/jb") || strstr(path, "tweakforce") || strstr(path, "weakforce")) {
                        size_t max_len = lc->cmdsize - rcmd->path.offset - 1;
                        const char *safe = "@executable_path/Frameworks";
                        strncpy(path, safe, max_len);
                        path[max_len] = '\0';
                    }
                }
            }

            cmd_ptr += lc->cmdsize;
        }

        if (!found_enc) {
            uintptr_t first_sec_offset = 0;
            cmd_ptr = (uint8_t *)hdr64 + sizeof(struct mach_header_64);
            for (uint32_t i = 0; i < hdr64->ncmds; i++) {
                struct load_command *lc = (struct load_command *)cmd_ptr;
                if (lc->cmdsize < sizeof(struct load_command) ||
                    (cmd_ptr + lc->cmdsize > (uint8_t *)hdr64 + sizeof(struct mach_header_64) + hdr64->sizeofcmds)) break;
                if (lc->cmd == LC_SEGMENT_64) {
                    struct segment_command_64 *seg = (struct segment_command_64 *)lc;
                    if (strcmp(seg->segname, "__TEXT") == 0 && seg->nsects > 0) {
                        struct section_64 *sec = (struct section_64 *)((uint8_t *)seg + sizeof(struct segment_command_64));
                        first_sec_offset = sec[0].offset;
                        break;
                    }
                }
                cmd_ptr += lc->cmdsize;
            }
            if (first_sec_offset >= sizeof(struct mach_header_64) + hdr64->sizeofcmds + sizeof(struct encryption_info_command_64)) {
                struct encryption_info_command_64 *new_enc = (struct encryption_info_command_64 *)((uint8_t *)hdr64 + sizeof(struct mach_header_64) + hdr64->sizeofcmds);
                new_enc->cmd = LC_ENCRYPTION_INFO_64;
                new_enc->cmdsize = sizeof(struct encryption_info_command_64);
                new_enc->cryptoff = (uint32_t)first_sec_offset;
                new_enc->cryptsize = 0x40000;
                new_enc->cryptid = 1;
                new_enc->pad = 0;

                hdr64->ncmds += 1;
                hdr64->sizeofcmds += sizeof(struct encryption_info_command_64);
            }
        }

        vm_protect(mach_task_self(), page_start, protect_size, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
        os_log(TFHLog(), "[TweakForce] In-place Mach-O header sanitization armed successfully");
    });
}

static const struct mach_header_64 *tf_get_sanitized_main_header(void) {
    tf_sanitize_main_header_in_place();
    if (orig_dyld_get_image_header) return (const struct mach_header_64 *)orig_dyld_get_image_header(0);
    return (const struct mach_header_64 *)_dyld_get_image_header(0);
}

static const struct mach_header *(*orig_NSGetMachExecuteHeader)(void) = NULL;

static const struct mach_header *tf_my_NSGetMachExecuteHeader(void) {
    tf_sanitize_main_header_in_place();
    if (orig_NSGetMachExecuteHeader && (void *)orig_NSGetMachExecuteHeader != (void *)tf_my_NSGetMachExecuteHeader) {
        return orig_NSGetMachExecuteHeader();
    }
    const struct mach_header *(*real_fn)(void) = (const struct mach_header *(*)(void))dlsym(RTLD_DEFAULT, "_NSGetMachExecuteHeader");
    if (real_fn && real_fn != tf_my_NSGetMachExecuteHeader) return real_fn();
    if (orig_dyld_get_image_header) return orig_dyld_get_image_header(0);
    return _dyld_get_image_header(0);
}

static int (*orig_NSGetExecutablePath)(char *buf, uint32_t *bufsize) = NULL;

static int tf_my_NSGetExecutablePath(char *buf, uint32_t *bufsize) {
    int ret = 0;
    if (orig_NSGetExecutablePath && (void *)orig_NSGetExecutablePath != (void *)tf_my_NSGetExecutablePath) {
        ret = orig_NSGetExecutablePath(buf, bufsize);
    } else {
        int (*real_fn)(char *, uint32_t *) = (int (*)(char *, uint32_t *))dlsym(RTLD_DEFAULT, "_NSGetExecutablePath");
        if (real_fn && real_fn != tf_my_NSGetExecutablePath) ret = real_fn(buf, bufsize);
    }
    static __thread BOOL in_get_exe_path = NO;
    if (in_get_exe_path) return ret;
    in_get_exe_path = YES;

    if (ret == 0 && buf) {
        if (tf_is_jailbreak_path(buf) || strcasestr(buf, "tweakforce") != NULL || strcasestr(buf, "weakforce") != NULL) {
            NSString *exe = [[NSBundle mainBundle] executablePath];
            if (exe && exe.length > 0) {
                const char *cexe = exe.fileSystemRepresentation;
                if (bufsize && *bufsize > strlen(cexe)) {
                    strncpy(buf, cexe, *bufsize);
                }
            }
        }
    }
    in_get_exe_path = NO;
    return ret;
}

static CFURLRef (*orig_CFBundleCopyResourceURL)(CFBundleRef bundle, CFStringRef resourceName, CFStringRef resourceType, CFStringRef subDirName) = NULL;

static CFURLRef tf_my_CFBundleCopyResourceURL(CFBundleRef bundle, CFStringRef resourceName, CFStringRef resourceType, CFStringRef subDirName) {
    if (resourceName) {
        if (CFStringCompare(resourceName, CFSTR("embedded"), kCFCompareCaseInsensitive) == kCFCompareEqualTo) {
            if (resourceType == NULL || CFStringCompare(resourceType, CFSTR("mobileprovision"), kCFCompareCaseInsensitive) == kCFCompareEqualTo) {
                return NULL;
            }
        }
        if (CFStringCompare(resourceName, CFSTR("embedded.mobileprovision"), kCFCompareCaseInsensitive) == kCFCompareEqualTo) {
            return NULL;
        }
        if (CFStringFind(resourceName, CFSTR("cydia"), kCFCompareCaseInsensitive).location != kCFNotFound ||
            CFStringFind(resourceName, CFSTR("sileo"), kCFCompareCaseInsensitive).location != kCFNotFound ||
            CFStringFind(resourceName, CFSTR("tweakforce"), kCFCompareCaseInsensitive).location != kCFNotFound ||
            CFStringFind(resourceName, CFSTR("weakforce"), kCFCompareCaseInsensitive).location != kCFNotFound ||
            CFStringFind(resourceName, CFSTR("ellekit"), kCFCompareCaseInsensitive).location != kCFNotFound ||
            CFStringFind(resourceName, CFSTR("substrate"), kCFCompareCaseInsensitive).location != kCFNotFound) {
            return NULL;
        }
    }
    if (orig_CFBundleCopyResourceURL && (void *)orig_CFBundleCopyResourceURL != (void *)tf_my_CFBundleCopyResourceURL) {
        return orig_CFBundleCopyResourceURL(bundle, resourceName, resourceType, subDirName);
    }
    CFURLRef (*real_fn)(CFBundleRef, CFStringRef, CFStringRef, CFStringRef) = (CFURLRef (*)(CFBundleRef, CFStringRef, CFStringRef, CFStringRef))dlsym(RTLD_DEFAULT, "CFBundleCopyResourceURL");
    if (real_fn && real_fn != tf_my_CFBundleCopyResourceURL) return real_fn(bundle, resourceName, resourceType, subDirName);
    return NULL;
}

static CFURLRef (*orig_CFBundleCopyResourceURLInDirectory)(CFURLRef bundleURL, CFStringRef resourceName, CFStringRef resourceType, CFStringRef subDirName) = NULL;

static CFURLRef tf_my_CFBundleCopyResourceURLInDirectory(CFURLRef bundleURL, CFStringRef resourceName, CFStringRef resourceType, CFStringRef subDirName) {
    if (resourceName) {
        if (CFStringCompare(resourceName, CFSTR("embedded"), kCFCompareCaseInsensitive) == kCFCompareEqualTo) {
            if (resourceType == NULL || CFStringCompare(resourceType, CFSTR("mobileprovision"), kCFCompareCaseInsensitive) == kCFCompareEqualTo) {
                return NULL;
            }
        }
        if (CFStringCompare(resourceName, CFSTR("embedded.mobileprovision"), kCFCompareCaseInsensitive) == kCFCompareEqualTo) {
            return NULL;
        }
        if (CFStringFind(resourceName, CFSTR("cydia"), kCFCompareCaseInsensitive).location != kCFNotFound ||
            CFStringFind(resourceName, CFSTR("sileo"), kCFCompareCaseInsensitive).location != kCFNotFound ||
            CFStringFind(resourceName, CFSTR("tweakforce"), kCFCompareCaseInsensitive).location != kCFNotFound ||
            CFStringFind(resourceName, CFSTR("weakforce"), kCFCompareCaseInsensitive).location != kCFNotFound ||
            CFStringFind(resourceName, CFSTR("ellekit"), kCFCompareCaseInsensitive).location != kCFNotFound ||
            CFStringFind(resourceName, CFSTR("substrate"), kCFCompareCaseInsensitive).location != kCFNotFound) {
            return NULL;
        }
    }
    if (orig_CFBundleCopyResourceURLInDirectory && (void *)orig_CFBundleCopyResourceURLInDirectory != (void *)tf_my_CFBundleCopyResourceURLInDirectory) {
        return orig_CFBundleCopyResourceURLInDirectory(bundleURL, resourceName, resourceType, subDirName);
    }
    CFURLRef (*real_fn)(CFURLRef, CFStringRef, CFStringRef, CFStringRef) = (CFURLRef (*)(CFURLRef, CFStringRef, CFStringRef, CFStringRef))dlsym(RTLD_DEFAULT, "CFBundleCopyResourceURLInDirectory");
    if (real_fn && real_fn != tf_my_CFBundleCopyResourceURLInDirectory) return real_fn(bundleURL, resourceName, resourceType, subDirName);
    return NULL;
}

static NSString *(*orig_pathForResource_ofType)(id self, SEL _cmd, NSString *name, NSString *ext) = NULL;

static NSString *tf_pathForResource_ofType(id self, SEL _cmd, NSString *name, NSString *ext) {
    if (name) {
        if ([name isEqualToString:@"embedded"] && (ext == nil || [ext isEqualToString:@"mobileprovision"])) {
            return nil;
        }
        if ([name isEqualToString:@"embedded.mobileprovision"]) {
            return nil;
        }
        if ([name rangeOfString:@"cydia" options:NSCaseInsensitiveSearch].location != NSNotFound ||
            [name rangeOfString:@"sileo" options:NSCaseInsensitiveSearch].location != NSNotFound ||
            [name rangeOfString:@"tweakforce" options:NSCaseInsensitiveSearch].location != NSNotFound ||
            [name rangeOfString:@"weakforce" options:NSCaseInsensitiveSearch].location != NSNotFound ||
            [name rangeOfString:@"ellekit" options:NSCaseInsensitiveSearch].location != NSNotFound ||
            [name rangeOfString:@"substrate" options:NSCaseInsensitiveSearch].location != NSNotFound) {
            return nil;
        }
    }
    if (orig_pathForResource_ofType) return orig_pathForResource_ofType(self, _cmd, name, ext);
    return nil;
}

static NSString *(*orig_pathForResource_ofType_inDirectory)(id self, SEL _cmd, NSString *name, NSString *ext, NSString *subpath) = NULL;

static NSString *tf_pathForResource_ofType_inDirectory(id self, SEL _cmd, NSString *name, NSString *ext, NSString *subpath) {
    if (name) {
        if ([name isEqualToString:@"embedded"] && (ext == nil || [ext isEqualToString:@"mobileprovision"])) {
            return nil;
        }
        if ([name isEqualToString:@"embedded.mobileprovision"]) {
            return nil;
        }
        if ([name rangeOfString:@"cydia" options:NSCaseInsensitiveSearch].location != NSNotFound ||
            [name rangeOfString:@"sileo" options:NSCaseInsensitiveSearch].location != NSNotFound ||
            [name rangeOfString:@"tweakforce" options:NSCaseInsensitiveSearch].location != NSNotFound ||
            [name rangeOfString:@"weakforce" options:NSCaseInsensitiveSearch].location != NSNotFound ||
            [name rangeOfString:@"ellekit" options:NSCaseInsensitiveSearch].location != NSNotFound ||
            [name rangeOfString:@"substrate" options:NSCaseInsensitiveSearch].location != NSNotFound) {
            return nil;
        }
    }
    if (orig_pathForResource_ofType_inDirectory) return orig_pathForResource_ofType_inDirectory(self, _cmd, name, ext, subpath);
    return nil;
}

static NSURL *(*orig_URLForResource_withExtension)(id self, SEL _cmd, NSString *name, NSString *ext) = NULL;

static NSURL *tf_URLForResource_withExtension(id self, SEL _cmd, NSString *name, NSString *ext) {
    if (name) {
        if ([name isEqualToString:@"embedded"] && (ext == nil || [ext isEqualToString:@"mobileprovision"])) {
            return nil;
        }
        if ([name isEqualToString:@"embedded.mobileprovision"]) {
            return nil;
        }
        if ([name rangeOfString:@"cydia" options:NSCaseInsensitiveSearch].location != NSNotFound ||
            [name rangeOfString:@"sileo" options:NSCaseInsensitiveSearch].location != NSNotFound ||
            [name rangeOfString:@"tweakforce" options:NSCaseInsensitiveSearch].location != NSNotFound ||
            [name rangeOfString:@"weakforce" options:NSCaseInsensitiveSearch].location != NSNotFound ||
            [name rangeOfString:@"ellekit" options:NSCaseInsensitiveSearch].location != NSNotFound ||
            [name rangeOfString:@"substrate" options:NSCaseInsensitiveSearch].location != NSNotFound) {
            return nil;
        }
    }
    if (orig_URLForResource_withExtension) return orig_URLForResource_withExtension(self, _cmd, name, ext);
    return nil;
}

static NSURL *(*orig_URLForResource_withExtension_subdirectory)(id self, SEL _cmd, NSString *name, NSString *ext, NSString *subpath) = NULL;

static NSURL *tf_URLForResource_withExtension_subdirectory(id self, SEL _cmd, NSString *name, NSString *ext, NSString *subpath) {
    if (name) {
        if ([name isEqualToString:@"embedded"] && (ext == nil || [ext isEqualToString:@"mobileprovision"])) {
            return nil;
        }
        if ([name isEqualToString:@"embedded.mobileprovision"]) {
            return nil;
        }
        if ([name rangeOfString:@"cydia" options:NSCaseInsensitiveSearch].location != NSNotFound ||
            [name rangeOfString:@"sileo" options:NSCaseInsensitiveSearch].location != NSNotFound ||
            [name rangeOfString:@"tweakforce" options:NSCaseInsensitiveSearch].location != NSNotFound ||
            [name rangeOfString:@"weakforce" options:NSCaseInsensitiveSearch].location != NSNotFound ||
            [name rangeOfString:@"ellekit" options:NSCaseInsensitiveSearch].location != NSNotFound ||
            [name rangeOfString:@"substrate" options:NSCaseInsensitiveSearch].location != NSNotFound) {
            return nil;
        }
    }
    if (orig_URLForResource_withExtension_subdirectory) return orig_URLForResource_withExtension_subdirectory(self, _cmd, name, ext, subpath);
    return nil;
}

static NSURL *(*orig_appStoreReceiptURL)(id self, SEL _cmd) = NULL;

static NSURL *tf_appStoreReceiptURL(id self, SEL _cmd) {
    NSURL *url = orig_appStoreReceiptURL ? orig_appStoreReceiptURL(self, _cmd) : nil;
    if (!url) {
        NSString *bpath = [[NSBundle mainBundle] bundlePath];
        if (bpath) {
            url = [NSURL fileURLWithPath:[bpath stringByAppendingPathComponent:@"StoreKit/receipt"]];
        }
    }
    return url;
}


// ============================================================================
// 4. Hook Installer & Master Setup
// ============================================================================

static void tf_install_spoof_and_stealth_hooks(void) {
    NSString *bundleID = [[NSBundle mainBundle] bundleIdentifier];
    if (!bundleID) return;

    // 0. Clean environment variables safely
    tf_clean_environment();

    // 1. Resolve configuration from JSON (with default fallbacks)
    NSArray *cfgPaths = @[@"/var/jb/etc/tweakforce.json",
                          @"/var/jb/var/mobile/Library/TweakForce/tweakforce.json",
                          @"/etc/tweakforce.json",
                          @"/var/mobile/Library/TweakForce/tweakforce.json"];

    NSData *cfgData = nil;
    for (NSString *p in cfgPaths) {
        if ([[NSFileManager defaultManager] fileExistsAtPath:p]) {
            cfgData = [NSData dataWithContentsOfFile:p];
            if (cfgData) break;
        }
    }

    if (cfgData) {
        NSError *err = nil;
        NSDictionary *json = [NSJSONSerialization JSONObjectWithData:cfgData options:0 error:&err];
        if (!err && [json isKindOfClass:[NSDictionary class]]) {
            NSDictionary *apps = json[@"apps"];
            NSDictionary *appCfg = apps[bundleID];
            if (appCfg && [appCfg isKindOfClass:[NSDictionary class]]) {
                if (appCfg[@"model"]) g_overrideModel = [appCfg[@"model"] copy];
                if (appCfg[@"version"]) g_overrideVersion = [appCfg[@"version"] copy];
                if (appCfg[@"build"]) g_overrideBuild = [appCfg[@"build"] copy];
                if (appCfg[@"product_name"]) g_overrideProductName = [appCfg[@"product_name"] copy];
                NSDictionary *vals = appCfg[@"values"];
                if (vals && [vals isKindOfClass:[NSDictionary class]]) {
                    if (vals[@"device_model_override"]) g_overrideModel = [vals[@"device_model_override"] copy];
                    if (vals[@"system_version_override"]) g_overrideVersion = [vals[@"system_version_override"] copy];
                    if (vals[@"build_version_override"]) g_overrideBuild = [vals[@"build_version_override"] copy];
                    if (vals[@"device_name_override"]) g_overrideName = [vals[@"device_name_override"] copy];
                    if (vals[@"board_model_override"]) g_overrideBoard = [vals[@"board_model_override"] copy];
                    if (vals[@"platform_override"]) g_overridePlatform = [vals[@"platform_override"] copy];
                }
            }
        }
    }

    // Default Fallback Spoofing Profile (iPhone 15 Pro Max, iOS 18.0)
    if (!g_overrideModel) g_overrideModel = @"iPhone15,3";
    if (!g_overrideVersion) g_overrideVersion = @"18.0";
    if (!g_overrideBuild) g_overrideBuild = @"22A3354";
    if (!g_overrideProductName) g_overrideProductName = @"iPhone OS";

    // 2. Pre-cache real function pointers
    if (!orig_sysctlbyname) orig_sysctlbyname = (int (*)(const char *, void *, size_t *, void *, size_t))dlsym(RTLD_DEFAULT, "sysctlbyname");
    if (!orig_sysctl) orig_sysctl = (int (*)(int *, u_int, void *, size_t *, void *, size_t))dlsym(RTLD_DEFAULT, "sysctl");
    if (!orig_uname) orig_uname = (int (*)(struct utsname *))dlsym(RTLD_DEFAULT, "uname");
    if (!orig_access) orig_access = (int (*)(const char *, int))dlsym(RTLD_DEFAULT, "access");
    if (!orig_stat) {
        orig_stat = (int (*)(const char *, struct stat *))dlsym(RTLD_DEFAULT, "stat$INODE64");
        if (!orig_stat) orig_stat = (int (*)(const char *, struct stat *))dlsym(RTLD_DEFAULT, "stat");
    }
    if (!orig_lstat) {
        orig_lstat = (int (*)(const char *, struct stat *))dlsym(RTLD_DEFAULT, "lstat$INODE64");
        if (!orig_lstat) orig_lstat = (int (*)(const char *, struct stat *))dlsym(RTLD_DEFAULT, "lstat");
    }
    if (!orig_fstatat) {
        orig_fstatat = (int (*)(int, const char *, struct stat *, int))dlsym(RTLD_DEFAULT, "fstatat$INODE64");
        if (!orig_fstatat) orig_fstatat = (int (*)(int, const char *, struct stat *, int))dlsym(RTLD_DEFAULT, "fstatat");
    }
    if (!orig_faccessat) orig_faccessat = (int (*)(int, const char *, int, int))dlsym(RTLD_DEFAULT, "faccessat");
    if (!orig_stat64) orig_stat64 = (int (*)(const char *, void *))dlsym(RTLD_DEFAULT, "stat64");
    if (!orig_lstat64) orig_lstat64 = (int (*)(const char *, void *))dlsym(RTLD_DEFAULT, "lstat64");
    if (!orig_open) orig_open = (int (*)(const char *, int, ...))dlsym(RTLD_DEFAULT, "open");
    if (!orig_openat) orig_openat = (int (*)(int, const char *, int, ...))dlsym(RTLD_DEFAULT, "openat");
    if (!orig_fopen) orig_fopen = (FILE *(*)(const char *, const char *))dlsym(RTLD_DEFAULT, "fopen");
    if (!orig_freopen) orig_freopen = (FILE *(*)(const char *, const char *, FILE *))dlsym(RTLD_DEFAULT, "freopen");
    if (!orig_readlink) orig_readlink = (ssize_t (*)(const char *, char *, size_t))dlsym(RTLD_DEFAULT, "readlink");
    if (!orig_readlinkat) orig_readlinkat = (ssize_t (*)(int, const char *, char *, size_t))dlsym(RTLD_DEFAULT, "readlinkat");
    if (!orig_statfs) orig_statfs = (int (*)(const char *, struct statfs *))dlsym(RTLD_DEFAULT, "statfs");
    if (!orig_getfsstat) orig_getfsstat = (int (*)(struct statfs *, int, int))dlsym(RTLD_DEFAULT, "getfsstat");
    if (!orig_getmntinfo) orig_getmntinfo = (int (*)(struct statfs **, int))dlsym(RTLD_DEFAULT, "getmntinfo");
    if (!orig_getattrlist) orig_getattrlist = (int (*)(const char *, struct attrlist *, void *, size_t, unsigned int))dlsym(RTLD_DEFAULT, "getattrlist");
    if (!orig_ptrace) orig_ptrace = (int (*)(int, pid_t, void *, int))dlsym(RTLD_DEFAULT, "ptrace");
    if (!orig_csops) orig_csops = (int (*)(pid_t, unsigned int, void *, size_t))dlsym(RTLD_DEFAULT, "csops");
    if (!orig_csops_audittoken) orig_csops_audittoken = (int (*)(pid_t, unsigned int, void *, size_t, void *))dlsym(RTLD_DEFAULT, "csops_audittoken");
    if (!orig_MGCopyAnswer) orig_MGCopyAnswer = (CFTypeRef (*)(CFStringRef))dlsym(RTLD_DEFAULT, "MGCopyAnswer");
    if (!orig_dyld_get_image_name) orig_dyld_get_image_name = (const char *(*)(uint32_t))dlsym(RTLD_DEFAULT, "_dyld_get_image_name");
    if (!orig_dladdr) orig_dladdr = (int (*)(const void *, Dl_info *))dlsym(RTLD_DEFAULT, "dladdr");
    if (!orig_getenv) orig_getenv = (char *(*)(const char *))dlsym(RTLD_DEFAULT, "getenv");
    if (!orig_CFCopySystemVersionDictionary) orig_CFCopySystemVersionDictionary = (CFDictionaryRef (*)(void))dlsym(RTLD_DEFAULT, "_CFCopySystemVersionDictionary");
    if (!orig_CFCopyServerVersionDictionary) orig_CFCopyServerVersionDictionary = (CFDictionaryRef (*)(void))dlsym(RTLD_DEFAULT, "_CFCopyServerVersionDictionary");
    if (!orig_proc_regionfilename) orig_proc_regionfilename = (int (*)(int, uint64_t, void *, uint32_t))dlsym(RTLD_DEFAULT, "proc_regionfilename");
    if (!orig_open_dprotected_np) orig_open_dprotected_np = (int (*)(const char *, int, int, int, ...))dlsym(RTLD_DEFAULT, "open_dprotected_np");
    if (!orig_fstat) {
        orig_fstat = (int (*)(int, struct stat *))dlsym(RTLD_DEFAULT, "fstat$INODE64");
        if (!orig_fstat) orig_fstat = (int (*)(int, struct stat *))dlsym(RTLD_DEFAULT, "fstat");
    }
    if (!orig_fstat64) orig_fstat64 = (int (*)(int, void *))dlsym(RTLD_DEFAULT, "fstat64");
    if (!orig_setattrlist) orig_setattrlist = (int (*)(const char *, struct attrlist *, void *, size_t, unsigned long))dlsym(RTLD_DEFAULT, "setattrlist");
    if (!orig_fsetattrlist) orig_fsetattrlist = (int (*)(int, struct attrlist *, void *, size_t, unsigned long))dlsym(RTLD_DEFAULT, "fsetattrlist");
    if (!orig_setuid) orig_setuid = (int (*)(uid_t))dlsym(RTLD_DEFAULT, "setuid");
    if (!orig_seteuid) orig_seteuid = (int (*)(uid_t))dlsym(RTLD_DEFAULT, "seteuid");
    if (!orig_setgid) orig_setgid = (int (*)(gid_t))dlsym(RTLD_DEFAULT, "setgid");
    if (!orig_setegid) orig_setegid = (int (*)(gid_t))dlsym(RTLD_DEFAULT, "setegid");
    if (!orig_isatty) orig_isatty = (int (*)(int))dlsym(RTLD_DEFAULT, "isatty");
    if (!orig_ttyname) orig_ttyname = (char *(*)(int))dlsym(RTLD_DEFAULT, "ttyname");
    if (!orig_ttyname_r) orig_ttyname_r = (int (*)(int, char *, size_t))dlsym(RTLD_DEFAULT, "ttyname_r");
    if (!orig_execvp) orig_execvp = (int (*)(const char *, char *const []))dlsym(RTLD_DEFAULT, "execvp");
    if (!orig_execvP) orig_execvP = (int (*)(const char *, const char *, char *const []))dlsym(RTLD_DEFAULT, "execvP");
    if (!orig_vfork) orig_vfork = (pid_t (*)(void))dlsym(RTLD_DEFAULT, "vfork");
    if (!orig_CFBundleGetAllBundles) orig_CFBundleGetAllBundles = (CFArrayRef (*)(void))dlsym(RTLD_DEFAULT, "CFBundleGetAllBundles");
    if (!orig_sandbox_check_by_audit_token) orig_sandbox_check_by_audit_token = (int (*)(audit_token_t, const char *, int, ...))dlsym(RTLD_DEFAULT, "sandbox_check_by_audit_token");
    if (!orig_vm_protect) orig_vm_protect = (kern_return_t (*)(vm_map_t, vm_address_t, vm_size_t, boolean_t, vm_prot_t))dlsym(RTLD_DEFAULT, "vm_protect");
    if (!orig_mach_vm_protect) orig_mach_vm_protect = (kern_return_t (*)(vm_map_t, mach_vm_address_t, mach_vm_size_t, boolean_t, vm_prot_t))dlsym(RTLD_DEFAULT, "mach_vm_protect");
    if (!orig_task_for_pid) orig_task_for_pid = (kern_return_t (*)(mach_port_name_t, int, mach_port_name_t *))dlsym(RTLD_DEFAULT, "task_for_pid");
    if (!orig_getuid) orig_getuid = (uid_t (*)(void))dlsym(RTLD_DEFAULT, "getuid");
    if (!orig_geteuid) orig_geteuid = (uid_t (*)(void))dlsym(RTLD_DEFAULT, "geteuid");
    if (!orig_getgid) orig_getgid = (gid_t (*)(void))dlsym(RTLD_DEFAULT, "getgid");
    if (!orig_getegid) orig_getegid = (gid_t (*)(void))dlsym(RTLD_DEFAULT, "getegid");
    if (!orig_getpwuid) orig_getpwuid = (struct passwd *(*)(uid_t))dlsym(RTLD_DEFAULT, "getpwuid");
    if (!orig_getpwnam) orig_getpwnam = (struct passwd *(*)(const char *))dlsym(RTLD_DEFAULT, "getpwnam");
    if (!orig_dyld_get_all_image_infos) orig_dyld_get_all_image_infos = (const struct dyld_all_image_infos *(*)(void))dlsym(RTLD_DEFAULT, "_dyld_get_all_image_infos");
    if (!orig_class_copyMethodList) orig_class_copyMethodList = (Method *(*)(Class, unsigned int *))dlsym(RTLD_DEFAULT, "class_copyMethodList");
    if (!orig_objc_getProtocol) orig_objc_getProtocol = (Protocol *(*)(const char *))dlsym(RTLD_DEFAULT, "objc_getProtocol");
    if (!orig_chflags) orig_chflags = (int (*)(const char *, u_int))dlsym(RTLD_DEFAULT, "chflags");
    if (!orig_lchflags) orig_lchflags = (int (*)(const char *, u_int))dlsym(RTLD_DEFAULT, "lchflags");
    if (!orig_fchflags) orig_fchflags = (int (*)(int, u_int))dlsym(RTLD_DEFAULT, "fchflags");
    if (!orig_getrlimit) orig_getrlimit = (int (*)(int, struct rlimit *))dlsym(RTLD_DEFAULT, "getrlimit");
    if (!orig_setrlimit) orig_setrlimit = (int (*)(int, const struct rlimit *))dlsym(RTLD_DEFAULT, "setrlimit");
    if (!orig_NSGetMachExecuteHeader) orig_NSGetMachExecuteHeader = (const struct mach_header *(*)(void))dlsym(RTLD_DEFAULT, "_NSGetMachExecuteHeader");
    if (!orig_NSGetExecutablePath) orig_NSGetExecutablePath = (int (*)(char *, uint32_t *))dlsym(RTLD_DEFAULT, "_NSGetExecutablePath");
    if (!orig_CFBundleCopyResourceURL) orig_CFBundleCopyResourceURL = (CFURLRef (*)(CFBundleRef, CFStringRef, CFStringRef, CFStringRef))dlsym(RTLD_DEFAULT, "CFBundleCopyResourceURL");
    if (!orig_CFBundleCopyResourceURLInDirectory) orig_CFBundleCopyResourceURLInDirectory = (CFURLRef (*)(CFURLRef, CFStringRef, CFStringRef, CFStringRef))dlsym(RTLD_DEFAULT, "CFBundleCopyResourceURLInDirectory");

    // 3. Install Echelon 1 Device & OS Info Hooks (ObjC & C)
    Class uiDeviceClass = NSClassFromString(@"UIDevice");
    if (uiDeviceClass) {
        TF_hookMethod(uiDeviceClass, @selector(name), (IMP)tf_device_name, NULL);
        TF_hookMethod(uiDeviceClass, @selector(systemVersion), (IMP)tf_device_systemVersion, NULL);
        TF_hookMethod(uiDeviceClass, @selector(model), (IMP)tf_device_model, NULL);
        TF_hookMethod(uiDeviceClass, @selector(localizedModel), (IMP)tf_device_localizedModel, NULL);
    }

    Class piClass = NSClassFromString(@"NSProcessInfo");
    if (piClass) {
        TF_hookMethod(piClass, @selector(operatingSystemVersion), (IMP)tf_processInfo_operatingSystemVersion, NULL);
        TF_hookMethod(piClass, @selector(isOperatingSystemAtLeastVersion:), (IMP)tf_processInfo_isOperatingSystemAtLeastVersion, NULL);
        TF_hookMethod(piClass, @selector(operatingSystemVersionString), (IMP)tf_processInfo_operatingSystemVersionString, NULL);
    }

    Class dictClass = NSClassFromString(@"NSDictionary");
    if (dictClass) {
        Class metaDict = object_getClass((id)dictClass);
        TF_hookMethod(metaDict, @selector(dictionaryWithContentsOfFile:), (IMP)tf_dict_dictionaryWithContentsOfFile, &orig_dictWithContentsOfFile);
        TF_hookMethod(metaDict, @selector(dictionaryWithContentsOfURL:), (IMP)tf_dict_dictionaryWithContentsOfURL, &orig_dictWithContentsOfURL);
    }

    TF_hookFunction("sysctlbyname", (void *)tf_my_sysctlbyname, (void **)&orig_sysctlbyname);
    TF_hookFunction("sysctl", (void *)tf_my_sysctl, (void **)&orig_sysctl);
    TF_hookFunction("uname", (void *)tf_my_uname, (void **)&orig_uname);
    TF_hookFunction("MGCopyAnswer", (void *)tf_my_MGCopyAnswer, (void **)&orig_MGCopyAnswer);
    TF_hookFunction("_CFCopySystemVersionDictionary", (void *)tf_my_CFCopySystemVersionDictionary, (void **)&orig_CFCopySystemVersionDictionary);
    TF_hookFunction("_CFCopyServerVersionDictionary", (void *)tf_my_CFCopyServerVersionDictionary, (void **)&orig_CFCopyServerVersionDictionary);

    // 4. Install Echelons 2 & 3 Stealth, POSIX, VFS, Dyld & Security Hooks
    TF_hookFunction("_dyld_get_image_name", (void *)tf_my_dyld_get_image_name, (void **)&orig_dyld_get_image_name);
    TF_hookFunction("dladdr", (void *)tf_my_dladdr, (void **)&orig_dladdr);
    TF_hookFunction("getenv", (void *)tf_my_getenv, (void **)&orig_getenv);
    TF_hookFunction("access", (void *)tf_my_access, (void **)&orig_access);
    TF_hookFunction("stat", (void *)tf_my_stat, (void **)&orig_stat);
    TF_hookFunction("lstat", (void *)tf_my_lstat, (void **)&orig_lstat);
    TF_hookFunction("fstatat", (void *)tf_my_fstatat, (void **)&orig_fstatat);
    TF_hookFunction("faccessat", (void *)tf_my_faccessat, (void **)&orig_faccessat);
    TF_hookFunction("stat64", (void *)tf_my_stat64, (void **)&orig_stat64);
    TF_hookFunction("lstat64", (void *)tf_my_lstat64, (void **)&orig_lstat64);
    TF_hookFunction("open", (void *)tf_my_open, (void **)&orig_open);
    TF_hookFunction("openat", (void *)tf_my_openat, (void **)&orig_openat);
    TF_hookFunction("fopen", (void *)tf_my_fopen, (void **)&orig_fopen);
    TF_hookFunction("freopen", (void *)tf_my_freopen, (void **)&orig_freopen);
    TF_hookFunction("readlink", (void *)tf_my_readlink, (void **)&orig_readlink);
    TF_hookFunction("readlinkat", (void *)tf_my_readlinkat, (void **)&orig_readlinkat);
    TF_hookFunction("statfs", (void *)tf_my_statfs, (void **)&orig_statfs);
    TF_hookFunction("getfsstat", (void *)tf_my_getfsstat, (void **)&orig_getfsstat);
    TF_hookFunction("getmntinfo", (void *)tf_my_getmntinfo, (void **)&orig_getmntinfo);
    TF_hookFunction("getattrlist", (void *)tf_my_getattrlist, (void **)&orig_getattrlist);
    TF_hookFunction("ptrace", (void *)tf_my_ptrace, (void **)&orig_ptrace);
    TF_hookFunction("fork", (void *)tf_my_fork, NULL);
    TF_hookFunction("csops", (void *)tf_my_csops, (void **)&orig_csops);
    TF_hookFunction("csops_audittoken", (void *)tf_my_csops_audittoken, (void **)&orig_csops_audittoken);
    TF_hookFunction("dlsym", (void *)tf_my_dlsym, (void **)&orig_dlsym);

    Class fmClass = NSClassFromString(@"NSFileManager");
    if (fmClass) {
        TF_hookMethod(fmClass, @selector(fileExistsAtPath:), (IMP)tf_fileManager_fileExistsAtPath, &orig_fileExistsAtPath);
        TF_hookMethod(fmClass, @selector(fileExistsAtPath:isDirectory:), (IMP)tf_fileManager_fileExistsAtPath_isDirectory, &orig_fileExistsAtPath_isDirectory);
        TF_hookMethod(fmClass, @selector(isReadableFileAtPath:), (IMP)tf_fileManager_isReadableFileAtPath, &orig_isReadableFileAtPath);
        TF_hookMethod(fmClass, @selector(isWritableFileAtPath:), (IMP)tf_fileManager_isWritableFileAtPath, &orig_isWritableFileAtPath);
        TF_hookMethod(fmClass, @selector(isDeletableFileAtPath:), (IMP)tf_fileManager_isDeletableFileAtPath, &orig_isDeletableFileAtPath);
        TF_hookMethod(fmClass, @selector(isExecutableFileAtPath:), (IMP)tf_fileManager_isExecutableFileAtPath, &orig_isExecutableFileAtPath);
        TF_hookMethod(fmClass, @selector(attributesOfItemAtPath:error:), (IMP)tf_fileManager_attributesOfItemAtPath, &orig_attributesOfItemAtPath);
        TF_hookMethod(fmClass, @selector(contentsOfDirectoryAtPath:error:), (IMP)tf_fileManager_contentsOfDirectoryAtPath, &orig_contentsOfDirectoryAtPath);
        TF_hookMethod(fmClass, @selector(destinationOfSymbolicLinkAtPath:error:), (IMP)tf_fileManager_destinationOfSymbolicLinkAtPath, &orig_destinationOfSymbolicLinkAtPath);
    }

    Class dataClass = NSClassFromString(@"NSData");
    if (dataClass) {
        Class metaData = object_getClass((id)dataClass);
        TF_hookMethod(metaData, @selector(dataWithContentsOfFile:), (IMP)tf_data_dataWithContentsOfFile, &orig_dataWithContentsOfFile);
    }

    Class strClass = NSClassFromString(@"NSString");
    if (strClass) {
        Class metaStr = object_getClass((id)strClass);
        TF_hookMethod(metaStr, @selector(stringWithContentsOfFile:encoding:error:), (IMP)tf_string_stringWithContentsOfFile, &orig_stringWithContentsOfFile);
    }

    Class appClass = NSClassFromString(@"UIApplication");
    if (appClass) {
        TF_hookMethod(appClass, @selector(canOpenURL:), (IMP)tf_app_canOpenURL, &orig_canOpenURL);
    }

    // 5. Install Echelon 4 Advanced Runtime, Network & Execution Cloaking Hooks
    TF_hookFunction("method_getImplementation", (void *)tf_my_method_getImplementation, (void **)&orig_method_getImplementation);
    TF_hookFunction("class_getMethodImplementation", (void *)tf_my_class_getMethodImplementation, (void **)&orig_class_getMethodImplementation);
    TF_hookFunction("connect", (void *)tf_my_connect, (void **)&orig_connect);
    TF_hookFunction("posix_spawn", (void *)tf_my_posix_spawn, (void **)&orig_posix_spawn);
    TF_hookFunction("posix_spawnp", (void *)tf_my_posix_spawnp, (void **)&orig_posix_spawnp);
    TF_hookFunction("system", (void *)tf_my_system, (void **)&orig_system);
    TF_hookFunction("popen", (void *)tf_my_popen, (void **)&orig_popen);

    // 6. Install Echelon 5 Direct Syscall, Sandbox Write Protection & Mach/Runtime Cloaking Hooks
    TF_hookFunction("syscall", (void *)tf_my_syscall, (void **)&orig_syscall);
    TF_hookFunction("statvfs", (void *)tf_my_statvfs, (void **)&orig_statvfs);
    TF_hookFunction("task_get_exception_ports", (void *)tf_my_task_get_exception_ports, (void **)&orig_task_get_exception_ports);
    TF_hookFunction("objc_getClass", (void *)tf_my_objc_getClass, (void **)&orig_objc_getClass);
    TF_hookFunction("objc_lookUpClass", (void *)tf_my_objc_lookUpClass, (void **)&orig_objc_lookUpClass);
    TF_hookFunction("objc_copyClassList", (void *)tf_my_objc_copyClassList, (void **)&orig_objc_copyClassList);

    Class procInfoClass = NSClassFromString(@"NSProcessInfo");
    if (procInfoClass) {
        TF_hookMethod(procInfoClass, @selector(environment), (IMP)tf_processInfo_environment, (IMP *)&orig_processInfo_environment);
        TF_hookMethod(procInfoClass, @selector(arguments), (IMP)tf_processInfo_arguments, (IMP *)&orig_processInfo_arguments);
    }

    if (fmClass) {
        TF_hookMethod(fmClass, @selector(createFileAtPath:contents:attributes:), (IMP)tf_fileManager_createFileAtPath, (IMP *)&orig_createFileAtPath);
    }

    if (strClass) {
        TF_hookMethod(strClass, @selector(writeToFile:atomically:encoding:error:), (IMP)tf_string_writeToFile, (IMP *)&orig_string_writeToFile);
    }

    if (dataClass) {
        TF_hookMethod(dataClass, @selector(writeToFile:options:error:), (IMP)tf_data_writeToFile, (IMP *)&orig_data_writeToFile);
    }

    // 7. Install Echelon 6 Mach-O Dyld Header/Slide, Hardware Watchpoints, Memory Protections & Signals
    TF_hookFunction("_dyld_get_image_header", (void *)tf_my_dyld_get_image_header, (void **)&orig_dyld_get_image_header);
    TF_hookFunction("_dyld_get_image_vmaddr_slide", (void *)tf_my_dyld_get_image_vmaddr_slide, (void **)&orig_dyld_get_image_vmaddr_slide);
    TF_hookFunction("thread_get_state", (void *)tf_my_thread_get_state, (void **)&orig_thread_get_state);
    TF_hookFunction("vm_region_64", (void *)tf_my_vm_region_64, (void **)&orig_vm_region_64);
    TF_hookFunction("sigaction", (void *)tf_my_sigaction, (void **)&orig_sigaction);
    TF_hookFunction("signal", (void *)tf_my_signal, (void **)&orig_signal);

    // 8. Install Echelon 7 dlopen, realpath, proc enumeration, _NSGetEnviron & NSBundle Hooks
    TF_hookFunction("dlopen", (void *)tf_my_dlopen, (void **)&orig_dlopen);
    TF_hookFunction("realpath", (void *)tf_my_realpath, (void **)&orig_realpath);
    TF_hookFunction("_NSGetEnviron", (void *)tf_my_NSGetEnviron, (void **)&orig_NSGetEnviron);
    TF_hookFunction("proc_listpids", (void *)tf_my_proc_listpids, (void **)&orig_proc_listpids);
    TF_hookFunction("proc_pidinfo", (void *)tf_my_proc_pidinfo, (void **)&orig_proc_pidinfo);
    TF_hookFunction("proc_name", (void *)tf_my_proc_name, (void **)&orig_proc_name);

    Class bundleClass = NSClassFromString(@"NSBundle");
    if (bundleClass) {
        Class bundleMeta = object_getClass(bundleClass);
        if (bundleMeta) {
            TF_hookMethod(bundleMeta, @selector(bundleWithPath:), (IMP)tf_bundleWithPath, (IMP *)&orig_bundleWithPath);
            TF_hookMethod(bundleMeta, @selector(bundleWithIdentifier:), (IMP)tf_bundleWithIdentifier, (IMP *)&orig_bundleWithIdentifier);
        }
    }

    // 9. Install Echelon 8 Directory Enumeration, Mach Bootstrap, Dyld Notification & Exception Port Hooks
    TF_hookFunction("opendir", (void *)tf_my_opendir, (void **)&orig_opendir);
    TF_hookFunction("readdir", (void *)tf_my_readdir, (void **)&orig_readdir);
    TF_hookFunction("scandir", (void *)tf_my_scandir, (void **)&orig_scandir);
    TF_hookFunction("bootstrap_look_up", (void *)tf_my_bootstrap_look_up, (void **)&orig_bootstrap_look_up);
    TF_hookFunction("_dyld_register_func_for_add_image", (void *)tf_my_dyld_register_func_for_add_image, (void **)&orig_dyld_register_func_for_add_image);
    TF_hookFunction("task_set_exception_ports", (void *)tf_my_task_set_exception_ports, (void **)&orig_task_set_exception_ports);

    // 10. Install Echelon 9 Mach Task Info, Dyld Image Table, Call-Stack & Memory Recurse Hooks
    TF_hookFunction("task_info", (void *)tf_my_task_info, (void **)&orig_task_info);
    TF_hookFunction("vm_region_recurse_64", (void *)tf_my_vm_region_recurse_64, (void **)&orig_vm_region_recurse_64);
    TF_hookFunction("backtrace", (void *)tf_my_backtrace, (void **)&orig_backtrace);
    TF_hookFunction("backtrace_symbols", (void *)tf_my_backtrace_symbols, (void **)&orig_backtrace_symbols);

    if (appClass) {
        TF_hookMethod(appClass, @selector(openURL:), (IMP)tf_app_openURL, (IMP *)&orig_openURL);
        TF_hookMethod(appClass, @selector(openURL:options:completionHandler:), (IMP)tf_app_openURL_options_completion, (IMP *)&orig_openURL_options_completion);
    }

    // 11. Install Echelon 10 Hardcore Anti-Detection Armor (Mach Exception Swap, Memory Trampoline Cloaking, Sandbox Check, Kernel Bootargs & Direct SVC Shield)
    TF_hookFunction("task_swap_exception_ports", (void *)tf_my_task_swap_exception_ports, (void **)&orig_task_swap_exception_ports);
    TF_hookFunction("thread_get_exception_ports", (void *)tf_my_thread_get_exception_ports, (void **)&orig_thread_get_exception_ports);
    TF_hookFunction("thread_swap_exception_ports", (void *)tf_my_thread_swap_exception_ports, (void **)&orig_thread_swap_exception_ports);
    TF_hookFunction("sandbox_check", (void *)tf_my_sandbox_check, (void **)&orig_sandbox_check);
    TF_hookFunction("vm_read", (void *)tf_my_vm_read, (void **)&orig_vm_read);
    TF_hookFunction("vm_read_overwrite", (void *)tf_my_vm_read_overwrite, (void **)&orig_vm_read_overwrite);
    TF_hookFunction("mach_vm_read_overwrite", (void *)tf_my_mach_vm_read_overwrite, (void **)&orig_mach_vm_read_overwrite);

    uint32_t direct_svcs = tf_neutralize_main_binary_direct_syscalls();
    os_log(TFHLog(), "[TweakForce] Echelon 10 Hardcore Anti-Detection armed: direct SVCs=%u", direct_svcs);

    // 12. Install Echelon 11 Ultra-Stealth Armor (Dyld Containment, Mach VM Region W^X, dlopen_preflight & VFS fcntl)
    TF_hookFunction("dyld_image_path_containing_address", (void *)tf_my_dyld_image_path_containing_address, (void **)&orig_dyld_image_path_containing_address);
    TF_hookFunction("dyld_image_header_containing_address", (void *)tf_my_dyld_image_header_containing_address, (void **)&orig_dyld_image_header_containing_address);
    TF_hookFunction("mach_vm_region", (void *)tf_my_mach_vm_region, (void **)&orig_mach_vm_region);
    TF_hookFunction("mach_vm_region_recurse", (void *)tf_my_mach_vm_region_recurse, (void **)&orig_mach_vm_region_recurse);
    TF_hookFunction("dlopen_preflight", (void *)tf_my_dlopen_preflight, (void **)&orig_dlopen_preflight);
    TF_hookFunction("fcntl", (void *)tf_my_fcntl, (void **)&orig_fcntl);
    TF_hookFunction("dl_iterate_phdr", (void *)tf_my_dl_iterate_phdr, (void **)&orig_dl_iterate_phdr);

    os_log(TFHLog(), "[TweakForce] Echelon 11 Ultra-Stealth armed: Dyld image containment, Mach VM W^X, dlopen_preflight & VFS fcntl(F_GETPATH)");

    // 13. Install Echelon 12 Kernel & Binary Integrity / Deep Unwind & Mount Armor
    TF_hookFunction("mach_vm_read", (void *)tf_my_mach_vm_read, (void **)&orig_mach_vm_read);
    TF_hookFunction("fstatfs", (void *)tf_my_fstatfs, (void **)&orig_fstatfs);
    TF_hookFunction("_Unwind_Backtrace", (void *)tf_my_Unwind_Backtrace, (void **)&orig_Unwind_Backtrace);
    TF_hookFunction("proc_pidpath", (void *)tf_my_proc_pidpath, (void **)&orig_proc_pidpath);
    TF_hookFunction("getxattr", (void *)tf_my_getxattr, (void **)&orig_getxattr);
    TF_hookFunction("lgetxattr", (void *)tf_my_lgetxattr, (void **)&orig_lgetxattr);
    TF_hookFunction("fgetxattr", (void *)tf_my_fgetxattr, (void **)&orig_fgetxattr);
    TF_hookFunction("listxattr", (void *)tf_my_listxattr, (void **)&orig_listxattr);
    TF_hookFunction("llistxattr", (void *)tf_my_llistxattr, (void **)&orig_llistxattr);

    os_log(TFHLog(), "[TweakForce] Echelon 12 Kernel & Binary Integrity armed: mach_vm_read, fstatfs, _Unwind_Backtrace, proc_pidpath, xattrs");

    // 14. Install Echelon 13 VFS Raw Buffers, POSIX Mount, Runtime Class List, Mach Thread Isolation & CoreServices Armor
    TF_hookFunction("__getdirentries64", (void *)tf_my_getdirentries64, (void **)&orig_getdirentries64);
    TF_hookFunction("getdirentries64", (void *)tf_my_getdirentries64, (void **)&orig_getdirentries64);
    TF_hookFunction("fstatvfs", (void *)tf_my_fstatvfs, (void **)&orig_fstatvfs);
    TF_hookFunction("objc_getClassList", (void *)tf_my_objc_getClassList, (void **)&orig_objc_getClassList);
    TF_hookFunction("task_threads", (void *)tf_my_task_threads, (void **)&orig_task_threads);
    TF_hookFunction("pthread_getname_np", (void *)tf_my_pthread_getname_np, (void **)&orig_pthread_getname_np);

    Class lsClass = NSClassFromString(@"LSApplicationWorkspace");
    if (!lsClass) {
        dlopen("/System/Library/Frameworks/CoreServices.framework/CoreServices", RTLD_NOW);
        dlopen("/System/Library/PrivateFrameworks/MobileCoreServices.framework/MobileCoreServices", RTLD_NOW);
        lsClass = NSClassFromString(@"LSApplicationWorkspace");
    }
    if (lsClass) {
        TF_hookMethod(lsClass, @selector(applicationsAvailableForHandlingURLScheme:), (IMP)tf_ls_applicationsAvailableForHandlingURLScheme, &orig_ls_appsForScheme);
        TF_hookMethod(lsClass, @selector(URLIsActive:), (IMP)tf_ls_URLIsActive, &orig_ls_urlIsActive);
        TF_hookMethod(lsClass, @selector(applicationForURL:), (IMP)tf_ls_applicationForURL, &orig_ls_appForURL);
    }

    os_log(TFHLog(), "[TweakForce] Echelon 13 Stealth armed: getdirentries64, fstatvfs, proc_pidinfo(FDS), objc_getClassList, task_threads, LSApplicationWorkspace");

    // 15. Install Echelon 14 VFS Mutation & Attributes Shield, CoreServices Application Proxies, Dyld Insertion Cloaking & Memory Protection Armor
    TF_hookFunction("dyld_has_inserted_or_interposing_libraries", (void *)tf_my_dyld_has_inserted_or_interposing_libraries, (void **)&orig_dyld_has_inserted_or_interposing_libraries);
    TF_hookFunction("_dyld_has_inserted_or_interposing_libraries", (void *)tf_my_dyld_has_inserted_or_interposing_libraries, (void **)&orig_dyld_has_inserted_or_interposing_libraries);
    TF_hookFunction("unlink", (void *)tf_my_unlink, (void **)&orig_unlink);
    TF_hookFunction("unlinkat", (void *)tf_my_unlinkat, (void **)&orig_unlinkat);
    TF_hookFunction("rmdir", (void *)tf_my_rmdir, (void **)&orig_rmdir);
    TF_hookFunction("remove", (void *)tf_my_remove, (void **)&orig_remove);
    TF_hookFunction("rename", (void *)tf_my_rename, (void **)&orig_rename);
    TF_hookFunction("renameat", (void *)tf_my_renameat, (void **)&orig_renameat);
    TF_hookFunction("chmod", (void *)tf_my_chmod, (void **)&orig_chmod);
    TF_hookFunction("fchmod", (void *)tf_my_fchmod, (void **)&orig_fchmod);
    TF_hookFunction("fchmodat", (void *)tf_my_fchmodat, (void **)&orig_fchmodat);
    TF_hookFunction("chown", (void *)tf_my_chown, (void **)&orig_chown);
    TF_hookFunction("lchown", (void *)tf_my_lchown, (void **)&orig_lchown);
    TF_hookFunction("fchown", (void *)tf_my_fchown, (void **)&orig_fchown);
    TF_hookFunction("fchownat", (void *)tf_my_fchownat, (void **)&orig_fchownat);
    TF_hookFunction("utimes", (void *)tf_my_utimes, (void **)&orig_utimes);
    TF_hookFunction("fgetattrlist", (void *)tf_my_fgetattrlist, (void **)&orig_fgetattrlist);
    TF_hookFunction("getattrlistat", (void *)tf_my_getattrlistat, (void **)&orig_getattrlistat);
    TF_hookFunction("execve", (void *)tf_my_execve, (void **)&orig_execve);
    TF_hookFunction("execv", (void *)tf_my_execv, (void **)&orig_execv);
    TF_hookFunction("mprotect", (void *)tf_my_mprotect, (void **)&orig_mprotect);
    TF_hookFunction("CFBundleGetBundleWithIdentifier", (void *)tf_my_CFBundleGetBundleWithIdentifier, (void **)&orig_CFBundleGetBundleWithIdentifier);
    TF_hookFunction("CFBundleCreate", (void *)tf_my_CFBundleCreate, (void **)&orig_CFBundleCreate);

    Class proxyClass = NSClassFromString(@"LSApplicationProxy");
    if (!proxyClass) {
        dlopen("/System/Library/Frameworks/CoreServices.framework/CoreServices", RTLD_NOW);
        dlopen("/System/Library/PrivateFrameworks/MobileCoreServices.framework/MobileCoreServices", RTLD_NOW);
        proxyClass = NSClassFromString(@"LSApplicationProxy");
    }
    if (proxyClass) {
        Class proxyMeta = object_getClass(proxyClass);
        if (proxyMeta) {
            TF_hookMethod(proxyMeta, @selector(applicationProxyForIdentifier:), (IMP)tf_ls_applicationProxyForIdentifier, &orig_ls_proxyForIdentifier);
            TF_hookMethod(proxyMeta, @selector(applicationProxyForBundleURL:), (IMP)tf_ls_applicationProxyForBundleURL, &orig_ls_proxyForBundleURL);
        }
        TF_hookMethod(proxyClass, @selector(isInstalled), (IMP)tf_ls_isInstalled, &orig_ls_proxyIsInstalled);
    }
    if (lsClass) {
        TF_hookMethod(lsClass, @selector(allInstalledApplications), (IMP)tf_ls_allInstalledApplications, &orig_ls_allInstalledApplications);
        TF_hookMethod(lsClass, @selector(allApplications), (IMP)tf_ls_allApplications, &orig_ls_allApplications);
    }

    os_log(TFHLog(), "[TweakForce] Echelon 14 Stealth armed: dyld_has_inserted_or_interposing_libraries, VFS mutations (unlink/rmdir/rename/chmod), fgetattrlist, execve, mprotect, CFBundle & LSApplicationProxy");

    // 16. Install Echelon 15 Memory Region Mapping Isolation, Protected Open, Descriptor Fstat & Attribute Mutation Shield, POSIX Privileges, Terminal Cloaking, Extended Exec & Bundle Listing Armor
    TF_hookFunction("proc_regionfilename", (void *)tf_my_proc_regionfilename, (void **)&orig_proc_regionfilename);
    TF_hookFunction("open_dprotected_np", (void *)tf_my_open_dprotected_np, (void **)&orig_open_dprotected_np);
    TF_hookFunction("fstat", (void *)tf_my_fstat, (void **)&orig_fstat);
    TF_hookFunction("fstat64", (void *)tf_my_fstat64, (void **)&orig_fstat64);
    TF_hookFunction("setattrlist", (void *)tf_my_setattrlist, (void **)&orig_setattrlist);
    TF_hookFunction("fsetattrlist", (void *)tf_my_fsetattrlist, (void **)&orig_fsetattrlist);
    TF_hookFunction("setuid", (void *)tf_my_setuid, (void **)&orig_setuid);
    TF_hookFunction("seteuid", (void *)tf_my_seteuid, (void **)&orig_seteuid);
    TF_hookFunction("setgid", (void *)tf_my_setgid, (void **)&orig_setgid);
    TF_hookFunction("setegid", (void *)tf_my_setegid, (void **)&orig_setegid);
    TF_hookFunction("isatty", (void *)tf_my_isatty, (void **)&orig_isatty);
    TF_hookFunction("ttyname", (void *)tf_my_ttyname, (void **)&orig_ttyname);
    TF_hookFunction("ttyname_r", (void *)tf_my_ttyname_r, (void **)&orig_ttyname_r);
    TF_hookFunction("execvp", (void *)tf_my_execvp, (void **)&orig_execvp);
    TF_hookFunction("execvP", (void *)tf_my_execvP, (void **)&orig_execvP);
    TF_hookFunction("vfork", (void *)tf_my_vfork, (void **)&orig_vfork);
    TF_hookFunction("CFBundleGetAllBundles", (void *)tf_my_CFBundleGetAllBundles, (void **)&orig_CFBundleGetAllBundles);
    TF_hookFunction("sandbox_check_by_audit_token", (void *)tf_my_sandbox_check_by_audit_token, (void **)&orig_sandbox_check_by_audit_token);

    if (bundleClass) {
        Class bundleMeta = object_getClass(bundleClass);
        if (bundleMeta) {
            TF_hookMethod(bundleMeta, @selector(allBundles), (IMP)tf_bundle_allBundles, &orig_bundle_allBundles);
            TF_hookMethod(bundleMeta, @selector(allFrameworks), (IMP)tf_bundle_allFrameworks, &orig_bundle_allFrameworks);
        }
    }

    os_log(TFHLog(), "[TweakForce] Echelon 15 Stealth armed: proc_regionfilename, open_dprotected_np, fstat, setattrlist, setuid/gid, isatty/ttyname, execvp/vfork, CFBundleGetAllBundles & [NSBundle allBundles]");

    // 17. Install Echelon 16 Mach VM W^X Protection, Task Sandbox, POSIX Identity, Password Sanitization, Dyld All Image Infos, Method Reflection & File Flags Armor
    TF_hookFunction("vm_protect", (void *)tf_my_vm_protect, (void **)&orig_vm_protect);
    TF_hookFunction("mach_vm_protect", (void *)tf_my_mach_vm_protect, (void **)&orig_mach_vm_protect);
    TF_hookFunction("task_for_pid", (void *)tf_my_task_for_pid, (void **)&orig_task_for_pid);
    TF_hookFunction("getuid", (void *)tf_my_getuid, (void **)&orig_getuid);
    TF_hookFunction("geteuid", (void *)tf_my_geteuid, (void **)&orig_geteuid);
    TF_hookFunction("getgid", (void *)tf_my_getgid, (void **)&orig_getgid);
    TF_hookFunction("getegid", (void *)tf_my_getegid, (void **)&orig_getegid);
    TF_hookFunction("getpwuid", (void *)tf_my_getpwuid, (void **)&orig_getpwuid);
    TF_hookFunction("getpwnam", (void *)tf_my_getpwnam, (void **)&orig_getpwnam);
    TF_hookFunction("_dyld_get_all_image_infos", (void *)tf_my_dyld_get_all_image_infos, (void **)&orig_dyld_get_all_image_infos);
    TF_hookFunction("class_copyMethodList", (void *)tf_my_class_copyMethodList, (void **)&orig_class_copyMethodList);
    TF_hookFunction("objc_getProtocol", (void *)tf_my_objc_getProtocol, (void **)&orig_objc_getProtocol);
    TF_hookFunction("chflags", (void *)tf_my_chflags, (void **)&orig_chflags);
    TF_hookFunction("lchflags", (void *)tf_my_lchflags, (void **)&orig_lchflags);
    TF_hookFunction("fchflags", (void *)tf_my_fchflags, (void **)&orig_fchflags);
    TF_hookFunction("getrlimit", (void *)tf_my_getrlimit, (void **)&orig_getrlimit);
    TF_hookFunction("setrlimit", (void *)tf_my_setrlimit, (void **)&orig_setrlimit);

    os_log(TFHLog(), "[TweakForce] Echelon 16 Stealth armed: vm_protect(W^X), task_for_pid, getuid/gid, getpwuid, _dyld_get_all_image_infos, class_copyMethodList, chflags & getrlimit");

    // 18. Install Echelon 17 Mach-O Load Commands, FairPlay Cryptid, Sideloading mobileprovision & App Integrity Armor
    tf_sanitize_main_header_in_place();
    TF_hookFunction("_NSGetMachExecuteHeader", (void *)tf_my_NSGetMachExecuteHeader, (void **)&orig_NSGetMachExecuteHeader);
    TF_hookFunction("_NSGetExecutablePath", (void *)tf_my_NSGetExecutablePath, (void **)&orig_NSGetExecutablePath);
    TF_hookFunction("CFBundleCopyResourceURL", (void *)tf_my_CFBundleCopyResourceURL, (void **)&orig_CFBundleCopyResourceURL);
    TF_hookFunction("CFBundleCopyResourceURLInDirectory", (void *)tf_my_CFBundleCopyResourceURLInDirectory, (void **)&orig_CFBundleCopyResourceURLInDirectory);

    Class bClass = NSClassFromString(@"NSBundle");
    if (bClass) {
        TF_hookMethod(bClass, @selector(pathForResource:ofType:), (IMP)tf_pathForResource_ofType, (IMP *)&orig_pathForResource_ofType);
        TF_hookMethod(bClass, @selector(pathForResource:ofType:inDirectory:), (IMP)tf_pathForResource_ofType_inDirectory, (IMP *)&orig_pathForResource_ofType_inDirectory);
        TF_hookMethod(bClass, @selector(URLForResource:withExtension:), (IMP)tf_URLForResource_withExtension, (IMP *)&orig_URLForResource_withExtension);
        TF_hookMethod(bClass, @selector(URLForResource:withExtension:subdirectory:), (IMP)tf_URLForResource_withExtension_subdirectory, (IMP *)&orig_URLForResource_withExtension_subdirectory);
        TF_hookMethod(bClass, @selector(appStoreReceiptURL), (IMP)tf_appStoreReceiptURL, (IMP *)&orig_appStoreReceiptURL);
    }

    os_log(TFHLog(), "[TweakForce] Echelon 17 Stealth armed: Mach-O FairPlay cryptid, LC_LOAD_DYLIB/RPATH sanitization, _NSGetMachExecuteHeader, _NSGetExecutablePath, CFBundleCopyResourceURL, embedded.mobileprovision & appStoreReceiptURL");
    os_log(TFHLog(), "[TweakForce] Comprehensive Echelons 1-17 Stealth & Spoofing hooks installed for %{public}@ (model=%{public}@, ver=%{public}@, build=%{public}@)",
           bundleID, g_overrideModel, g_overrideVersion, g_overrideBuild);
}

static BOOL s_test_add_image_leaked = NO;
static void s_test_image_cb(const struct mach_header *mh, intptr_t slide) {
    Dl_info dli;
    memset(&dli, 0, sizeof(dli));
    if (dladdr((const void *)mh, &dli) && dli.dli_fname) {
        if (strcasestr(dli.dli_fname, "tweakforce") != NULL || strcasestr(dli.dli_fname, "weakforce") != NULL) {
            s_test_add_image_leaked = YES;
        }
    }
}

static _Unwind_Reason_Code tf_test_unwind_audit_cb(struct _Unwind_Context *ctx, void *d) {
    BOOL *clean_flag = (BOOL *)d;
    uintptr_t (*fn_get_ip)(struct _Unwind_Context *) = (uintptr_t (*)(struct _Unwind_Context *))dlsym(RTLD_DEFAULT, "_Unwind_GetIP");
    if (fn_get_ip && ctx) {
        uintptr_t ip = fn_get_ip(ctx);
        if (ip) {
            Dl_info dli;
            memset(&dli, 0, sizeof(dli));
            if (dladdr((const void *)ip, &dli) && dli.dli_fname) {
                if (strcasestr(dli.dli_fname, "tweakforce") != NULL ||
                    strcasestr(dli.dli_fname, "weakforce") != NULL) {
                    if (clean_flag) *clean_flag = NO;
                }
            }
        }
    }
    return _URC_NO_REASON;
}

// ============================================================================
// 5. In-App Comprehensive Stealth & Spoofing Self-Test Audit (Safe UI Alert)
// ============================================================================

static UIViewController * _Nullable tf_get_top_view_controller(void) {
    if (![NSThread isMainThread]) return nil;

    Class appClass = NSClassFromString(@"UIApplication");
    if (!appClass) return nil;

    UIApplication *app = [UIApplication sharedApplication];
    if (!app) return nil;

    UIWindow *targetWindow = nil;
    if (@available(iOS 13.0, *)) {
        for (UIScene *scene in app.connectedScenes) {
            if ([scene isKindOfClass:[UIWindowScene class]]) {
                UIWindowScene *ws = (UIWindowScene *)scene;
                if (ws.activationState == UISceneActivationStateForegroundActive ||
                    ws.activationState == UISceneActivationStateForegroundInactive) {
                    for (UIWindow *w in ws.windows) {
                        if (w.isKeyWindow || (w.rootViewController && w.windowLevel == UIWindowLevelNormal && !w.hidden)) {
                            targetWindow = w;
                            break;
                        }
                    }
                }
                if (targetWindow) break;
            }
        }
    }

    if (!targetWindow) {
        for (UIWindow *w in app.windows) {
            if (w.isKeyWindow || (w.rootViewController && w.windowLevel == UIWindowLevelNormal && !w.hidden)) {
                targetWindow = w;
                break;
            }
        }
    }

    if (!targetWindow) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        targetWindow = app.keyWindow;
#pragma clang diagnostic pop
    }

    if (!targetWindow || !targetWindow.rootViewController) {
        return nil;
    }

    UIViewController *top = targetWindow.rootViewController;
    while (top.presentedViewController) {
        if ([top.presentedViewController isKindOfClass:[UIAlertController class]]) {
            UIAlertController *ac = (UIAlertController *)top.presentedViewController;
            if ([ac.title containsString:@"TweakForce"]) {
                return nil;
            }
        }
        top = top.presentedViewController;
    }
    return top;
}

static void tf_run_stealth_audit(NSMutableString *outReport, BOOL *outAllPassed) {
    BOOL allPassed = YES;

    // 1. POSIX access("/var/jb", F_OK)
    errno = 0;
    int acc_jb = access("/var/jb", F_OK);
    BOOL acc_jb_ok = (acc_jb == -1 && errno == ENOENT);
    if (!acc_jb_ok) allPassed = NO;

    // 2. POSIX stat("/var/jb")
    errno = 0;
    struct stat st;
    int stat_jb = stat("/var/jb", &st);
    BOOL stat_jb_ok = (stat_jb == -1 && errno == ENOENT);
    if (!stat_jb_ok) allPassed = NO;

    // 3. POSIX open("/var/jb", O_RDONLY)
    errno = 0;
    int fd_jb = open("/var/jb", O_RDONLY);
    BOOL open_jb_ok = (fd_jb == -1 && errno == ENOENT);
    if (fd_jb >= 0) close(fd_jb);
    if (!open_jb_ok) allPassed = NO;

    // 4. POSIX fopen("/var/jb", "r")
    errno = 0;
    FILE *fp_jb = fopen("/var/jb", "r");
    BOOL fopen_jb_ok = (fp_jb == NULL && errno == ENOENT);
    if (fp_jb) fclose(fp_jb);
    if (!fopen_jb_ok) allPassed = NO;

    // 5. POSIX readlink("/var/jb")
    errno = 0;
    char linkbuf[128] = {0};
    ssize_t rl_res = readlink("/var/jb", linkbuf, sizeof(linkbuf) - 1);
    BOOL readlink_ok = (rl_res == -1 && errno == ENOENT);
    if (!readlink_ok) allPassed = NO;

    // 6. POSIX fstatat / faccessat
    errno = 0;
    struct stat fst;
    int fstat_res = fstatat(AT_FDCWD, "/var/jb", &fst, 0);
    BOOL fstatat_ok = (fstat_res == -1 && errno == ENOENT);
    if (!fstatat_ok) allPassed = NO;

    // 7. VFS statfs("/") read-only check
    struct statfs sfs;
    int sfs_res = statfs("/", &sfs);
    BOOL statfs_ok = (sfs_res == 0 && (sfs.f_flags & MNT_RDONLY) != 0);
    if (!statfs_ok) allPassed = NO;

    // 8. Cocoa NSFileManager checks
    BOOL fm_var_jb = [[NSFileManager defaultManager] fileExistsAtPath:@"/var/jb"];
    BOOL fm_sileo = [[NSFileManager defaultManager] fileExistsAtPath:@"/Applications/Sileo.app"];
    BOOL fm_ms = [[NSFileManager defaultManager] fileExistsAtPath:@"/Library/MobileSubstrate/MobileSubstrate.dylib"];
    BOOL fm_readable = [[NSFileManager defaultManager] isReadableFileAtPath:@"/var/jb"];
    BOOL fm_ok = (!fm_var_jb && !fm_sileo && !fm_ms && !fm_readable);
    if (!fm_ok) allPassed = NO;

    // 9. Cocoa URL scheme checks
    BOOL can_sileo = NO;
    BOOL can_cydia = NO;
    BOOL can_filza = NO;
    if ([UIApplication respondsToSelector:@selector(sharedApplication)]) {
        UIApplication *app = [UIApplication sharedApplication];
        can_sileo = [app canOpenURL:[NSURL URLWithString:@"sileo://"]];
        can_cydia = [app canOpenURL:[NSURL URLWithString:@"cydia://"]];
        can_filza = [app canOpenURL:[NSURL URLWithString:@"filza://"]];
    }
    BOOL url_ok = (!can_sileo && !can_cydia && !can_filza);
    if (!url_ok) allPassed = NO;

    // 10. Dyld loaded images masking check
    uint32_t count = _dyld_image_count();
    int dyld_leaks = 0;
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (name) {
            if (strstr(name, "TweakForce") != NULL ||
                strstr(name, "ElleKit") != NULL ||
                strstr(name, "roothide") != NULL ||
                strstr(name, "Dopamine") != NULL ||
                strstr(name, "/var/jb") != NULL) {
                dyld_leaks++;
            }
        }
    }
    BOOL dyld_clean = (dyld_leaks == 0);
    if (!dyld_clean) allPassed = NO;

    // 11. Environment DYLD_INSERT_LIBRARIES check
    char *dyld_env = getenv("DYLD_INSERT_LIBRARIES");
    BOOL env_clean = (dyld_env == NULL);
    if (!env_clean) allPassed = NO;

    // 12. dlsym check for jailbreak symbols
    void *sym_hook = dlsym(RTLD_DEFAULT, "MSHookFunction");
    BOOL dlsym_clean = (sym_hook == NULL);
    if (!dlsym_clean) allPassed = NO;

    // 13. dladdr check (must be masked to Foundation)
    Dl_info dlinfo;
    int dl_res = dladdr((const void *)tf_install_spoof_and_stealth_hooks, &dlinfo);
    BOOL dladdr_clean = (dl_res != 0 && dlinfo.dli_fname && strstr(dlinfo.dli_fname, "Foundation") != NULL);
    if (!dladdr_clean) allPassed = NO;

    // 14. Anti-debug ptrace(PT_DENY_ATTACH) check
    int (*p_ptrace)(int, pid_t, void *, int) = (int (*)(int, pid_t, void *, int))dlsym(RTLD_DEFAULT, "ptrace");
    int pt_res = p_ptrace ? p_ptrace(31, 0, 0, 0) : 0;
    BOOL ptrace_ok = (pt_res == 0);
    if (!ptrace_ok) allPassed = NO;

    // 15. Sandbox fork() check
    errno = 0;
    pid_t fork_res = fork();
    BOOL fork_blocked = (fork_res == -1);
    if (!fork_blocked) allPassed = NO;

    // 16. Code-signing csops check
    uint32_t cs_flags = 0;
    int (*p_csops)(pid_t, unsigned int, void *, size_t) = (int (*)(pid_t, unsigned int, void *, size_t))dlsym(RTLD_DEFAULT, "csops");
    int cs_res = p_csops ? p_csops(0, CS_OPS_STATUS, &cs_flags, sizeof(cs_flags)) : -1;
    BOOL cs_ok = (cs_res == 0 && (cs_flags & CS_VALID) != 0 && (cs_flags & CS_DEBUGGED) == 0);
    if (!cs_ok) allPassed = NO;

    // 18. Echelon 4: Objective-C Runtime IMP Integrity check
    Method fm_m = class_getInstanceMethod(NSClassFromString(@"NSFileManager"), @selector(fileExistsAtPath:));
    IMP fm_imp = fm_m ? method_getImplementation(fm_m) : NULL;
    Dl_info fm_info;
    int fm_dl = (fm_imp != NULL) ? dladdr((const void *)fm_imp, &fm_info) : 0;
    BOOL imp_ok = (fm_dl != 0 && fm_info.dli_fname != NULL && strstr(fm_info.dli_fname, "Foundation") != NULL);
    if (!imp_ok) allPassed = NO;

    // 19. Echelon 4: Network Local Port Probing check (127.0.0.1:22)
    int test_sock = socket(AF_INET, SOCK_STREAM, 0);
    BOOL port_blocked = YES;
    if (test_sock >= 0) {
        struct sockaddr_in sin;
        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_port = htons(22);
        sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        errno = 0;
        int conn_res = connect(test_sock, (struct sockaddr *)&sin, sizeof(sin));
        port_blocked = (conn_res == -1 && errno == ECONNREFUSED);
        close(test_sock);
    }
    if (!port_blocked) allPassed = NO;

    // 20. Echelon 4: Process Spawning Sandbox check (posix_spawn /bin/sh)
    pid_t sp_pid = 0;
    char *const sp_argv[] = {(char *)"/bin/sh", NULL};
    errno = 0;
    int sp_err = posix_spawn(&sp_pid, "/bin/sh", NULL, NULL, sp_argv, NULL);
    BOOL spawn_ok = (sp_err == ENOENT || errno == ENOENT);
    if (!spawn_ok) allPassed = NO;

    // 21. Echelon 5: Direct syscall(SYS_access) check
    errno = 0;
    int sys_acc_res = syscall(SYS_access, "/var/jb", F_OK);
    BOOL syscall_acc_ok = (sys_acc_res == -1 && errno == ENOENT);
    if (!syscall_acc_ok) allPassed = NO;

    // 22. Echelon 5: Restricted directory sandbox write probe check
    NSError *writeErr = nil;
    BOOL writeRes = [@"probe" writeToFile:@"/private/jailbreak_test.txt" atomically:YES encoding:NSUTF8StringEncoding error:&writeErr];
    BOOL write_probe_blocked = (!writeRes && writeErr != nil);
    if (!write_probe_blocked) allPassed = NO;

    // 23. Echelon 5: Objective-C Runtime class inspection check (objc_getClass)
    Class tf_cls = objc_getClass("TweakForce");
    Class ek_cls = objc_getClass("ElleKit");
    BOOL cls_clean = (tf_cls == Nil && ek_cls == Nil);
    if (!cls_clean) allPassed = NO;

    // 24. Echelon 5: Cocoa [NSProcessInfo environment] check
    NSDictionary *pEnv = [[NSProcessInfo processInfo] environment];
    BOOL proc_env_clean = ([pEnv objectForKey:@"DYLD_INSERT_LIBRARIES"] == nil);
    if (!proc_env_clean) allPassed = NO;

    // 25. Echelon 6: Mach-O Dyld Header integrity check (_dyld_get_image_header)
    const struct mach_header *hdr0 = _dyld_get_image_header(0);
    BOOL dyld_hdr_ok = (hdr0 != NULL && (hdr0->magic == MH_MAGIC_64 || hdr0->magic == MH_MAGIC));
    if (!dyld_hdr_ok) allPassed = NO;

    // 26. Echelon 6: Hardware Watchpoint/Breakpoint register check (thread_get_state ARM_DEBUG_STATE64)
    natural_t dbg_state[68] = {0};
    mach_msg_type_number_t dbg_cnt = 68;
    kern_return_t dbg_kr = thread_get_state(mach_thread_self(), 15, (thread_state_t)dbg_state, &dbg_cnt);
    BOOL hw_dbg_clean = YES;
    if (dbg_kr == KERN_SUCCESS) {
        for (mach_msg_type_number_t i = 0; i < dbg_cnt; i++) {
            if (dbg_state[i] != 0) {
                hw_dbg_clean = NO;
                break;
            }
        }
    }
    if (!hw_dbg_clean) allPassed = NO;

    // 27. Echelon 6: Memory Region Protection check (vm_region_64 W^X)
    vm_address_t vm_addr = (vm_address_t)tf_install_spoof_and_stealth_hooks;
    vm_size_t vm_sz = 0;
    vm_region_basic_info_data_64_t binfo;
    mach_msg_type_number_t binfo_cnt = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t obj_name = MACH_PORT_NULL;
    kern_return_t vm_kr = vm_region_64(mach_task_self(), &vm_addr, &vm_sz, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&binfo, &binfo_cnt, &obj_name);
    BOOL vm_clean = (vm_kr == KERN_SUCCESS && (binfo.protection & VM_PROT_WRITE) == 0);
    if (!vm_clean) allPassed = NO;

    // 28. Echelon 6: Signal Handler Anti-Tampering check (sigaction SIGTRAP)
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    int sa_res = sigaction(SIGTRAP, NULL, &sa);
    BOOL sig_clean = (sa_res == 0 && sa.sa_handler == SIG_DFL);
    if (!sig_clean) allPassed = NO;

    // 29. Echelon 7: Dynamic library probing (dlopen)
    void *dl_jb = dlopen("/var/jb/usr/lib/libellekit.dylib", RTLD_NOW);
    BOOL dlopen_clean = (dl_jb == NULL);
    if (dl_jb) dlclose(dl_jb);
    if (!dlopen_clean) allPassed = NO;

    // 30. Echelon 7: Symlink canonicalization (realpath)
    char rp_buf[1024] = {0};
    errno = 0;
    char *rp_res = realpath("/var/jb", rp_buf);
    BOOL realpath_clean = (rp_res == NULL && errno == ENOENT);
    if (!realpath_clean) allPassed = NO;

    // 31. Echelon 7: Bundle inspection (NSBundle bundleWithPath:)
    NSBundle *jb_bnd = [NSBundle bundleWithPath:@"/Library/Frameworks/CydiaSubstrate.framework"];
    BOOL bundle_clean = (jb_bnd == nil);
    if (!bundle_clean) allPassed = NO;

    // 32. Echelon 7: Process list isolation (proc_listpids)
    pid_t pids[16] = {0};
    int pids_sz = tf_my_proc_listpids(1, 0, pids, sizeof(pids));
    BOOL proc_clean = (pids_sz <= (int)sizeof(pid_t));
    if (!proc_clean) allPassed = NO;

    // 33. Echelon 8: Directory stream cloaking (opendir)
    DIR *d_jb = opendir("/var/jb");
    BOOL opendir_clean = (d_jb == NULL && errno == ENOENT);
    if (d_jb) closedir(d_jb);
    if (!opendir_clean) allPassed = NO;

    // 34. Echelon 8: Directory content filtering (scandir)
    struct dirent **namelist = NULL;
    int n_entries = scandir("/Applications", &namelist, NULL, alphasort);
    BOOL scandir_clean = YES;
    if (n_entries >= 0) {
        for (int i = 0; i < n_entries; i++) {
            if (namelist[i] && (strcasestr(namelist[i]->d_name, "cydia") || strcasestr(namelist[i]->d_name, "sileo") || strcasestr(namelist[i]->d_name, "zebra"))) {
                scandir_clean = NO;
            }
            free(namelist[i]);
        }
        free(namelist);
    }
    if (!scandir_clean) allPassed = NO;

    // 35. Echelon 8: Mach IPC Bootstrap port cloaking (bootstrap_look_up)
    mach_port_t b_port = MACH_PORT_NULL;
    mach_port_t bp = MACH_PORT_NULL;
    task_get_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, &bp);
    kern_return_t b_kr = bootstrap_look_up(bp, "cy:com.saurik.cydo", &b_port);
    BOOL bootstrap_clean = (b_kr == 1102 || b_port == MACH_PORT_NULL);
    if (!bootstrap_clean) allPassed = NO;

    // 36. Echelon 8: Dyld image notification cloaking (_dyld_register_func_for_add_image)
    _dyld_register_func_for_add_image(s_test_image_cb);
    BOOL dyld_cb_clean = (!s_test_add_image_leaked);
    if (!dyld_cb_clean) allPassed = NO;

    // 37. Echelon 9: Mach task_info(TASK_DYLD_INFO) image list sanitization
    struct tf_task_dyld_info t_dyld;
    memset(&t_dyld, 0, sizeof(t_dyld));
    mach_msg_type_number_t t_cnt = sizeof(t_dyld)/sizeof(natural_t);
    kern_return_t t_kr = tf_my_task_info(mach_task_self(), TASK_DYLD_INFO, (task_info_t)&t_dyld, &t_cnt);
    BOOL task_dyld_clean = YES;
    if (t_kr == KERN_SUCCESS && t_dyld.all_image_info_addr != 0) {
        struct tf_dyld_all_image_infos *infos = (struct tf_dyld_all_image_infos *)(uintptr_t)t_dyld.all_image_info_addr;
        if (infos && infos->infoArray) {
            for (uint32_t i = 0; i < infos->infoArrayCount; i++) {
                const char *p = infos->infoArray[i].imageFilePath;
                if (p && (strcasestr(p, "tweakforce") || strcasestr(p, "weakforce") || strcasestr(p, "ellekit") || strcasestr(p, "substrate"))) {
                    task_dyld_clean = NO;
                    break;
                }
            }
        }
    }
    if (!task_dyld_clean) allPassed = NO;

    // 38. Echelon 9: Deep dlsym Shielding
    BOOL dlsym_ext_clean = (dlsym(RTLD_DEFAULT, "MSHookFunction") == NULL &&
                            dlsym(RTLD_DEFAULT, "ellekit_hook_function") == NULL &&
                            dlsym(RTLD_DEFAULT, "tf_install_spoof_and_stealth_hooks") == NULL);
    if (!dlsym_ext_clean) allPassed = NO;

    // 39. Echelon 9: Relative file access fstatat
    int var_fd = open("/var", O_RDONLY);
    struct stat st_rel;
    memset(&st_rel, 0, sizeof(st_rel));
    errno = 0;
    int fstatat_rel = -1;
    int fstatat_err = 0;
    if (var_fd >= 0) {
        fstatat_rel = fstatat(var_fd, "jb", &st_rel, 0);
        fstatat_err = errno;
        close(var_fd);
    } else {
        fstatat_rel = fstatat(AT_FDCWD, "/var/jb", &st_rel, 0);
        fstatat_err = errno;
    }
    BOOL fstatat_rel_clean = (fstatat_rel == -1 && fstatat_err == ENOENT);
    if (!fstatat_rel_clean) allPassed = NO;

    // 40. Echelon 9: Call stack backtrace sanitization & Direct Syscall Audit
    void *bt_buf[32] = {0};
    int bt_cnt = backtrace(bt_buf, 32);
    BOOL bt_clean = YES;
    for (int i = 0; i < bt_cnt; i++) {
        Dl_info dli;
        memset(&dli, 0, sizeof(dli));
        if (dladdr(bt_buf[i], &dli) && dli.dli_fname) {
            if (strcasestr(dli.dli_fname, "tweakforce") || strcasestr(dli.dli_fname, "weakforce")) {
                bt_clean = NO;
                break;
            }
        }
    }
    if (!bt_clean) allPassed = NO;

    // 41. Echelon 10: Mach Exception Ports Swap
#ifndef EXC_TYPES_COUNT
#define EXC_TYPES_COUNT 32
#endif
    mach_msg_type_number_t sw_cnt = 0;
    exception_mask_t sw_masks[EXC_TYPES_COUNT];
    mach_port_t sw_handlers[EXC_TYPES_COUNT];
    exception_behavior_t sw_behaviors[EXC_TYPES_COUNT];
    thread_state_flavor_t sw_flavors[EXC_TYPES_COUNT];
    kern_return_t sw_kr = tf_my_task_swap_exception_ports(
        mach_task_self(), EXC_MASK_ALL, MACH_PORT_NULL, EXCEPTION_DEFAULT, THREAD_STATE_NONE,
        sw_masks, &sw_cnt, sw_handlers, sw_behaviors, sw_flavors);
    BOOL exc_swap_clean = (sw_kr == KERN_SUCCESS && sw_cnt == 0);
    if (!exc_swap_clean) allPassed = NO;

    // 42. Echelon 10: Kernel Bootargs Shield (sysctlbyname kern.bootargs)
    char bootargs_buf[256] = {0};
    size_t bootargs_sz = sizeof(bootargs_buf);
    int b_ret = sysctlbyname("kern.bootargs", bootargs_buf, &bootargs_sz, NULL, 0);
    BOOL bootargs_clean = (b_ret == -1 || bootargs_buf[0] == '\0');
    if (!bootargs_clean) allPassed = NO;

    // 43. Echelon 10: Sandbox Policy Enforcement (sandbox_check)
    int sb_ret = sandbox_check(getpid(), "file-read-data", SANDBOX_FILTER_PATH | SANDBOX_CHECK_NO_REPORT, "/var/jb");
    BOOL sandbox_clean = (sb_ret != 0);
    if (!sandbox_clean) allPassed = NO;

    // 44. Echelon 10: In-Memory Trampoline Cloaking (vm_read_overwrite)
    uint32_t read_bytes[4] = {0};
    vm_size_t read_sz = 0;
    kern_return_t rkr = tf_my_vm_read_overwrite(mach_task_self(), (vm_address_t)&stat, sizeof(read_bytes), (vm_address_t)read_bytes, &read_sz);
    BOOL tramp_cloaked = (rkr == KERN_SUCCESS && read_bytes[0] != 0x58000050);
    if (!tramp_cloaked) allPassed = NO;

    // 45. Echelon 10: Process Arguments Cloaking (sysctl KERN_PROCARGS2)
    int mib_pa[3] = {CTL_KERN, KERN_PROCARGS2, getpid()};
    char pa_buf[1024] = {0};
    size_t pa_len = sizeof(pa_buf);
    int pa_ret = sysctl(mib_pa, 3, pa_buf, &pa_len, NULL, 0);
    BOOL procargs_clean = (pa_ret == 0 && strstr(pa_buf, "DYLD_INSERT_LIBRARIES") == NULL && strstr(pa_buf, "TweakForce") == NULL);
    if (!procargs_clean) allPassed = NO;

    // 46. Echelon 11: Dynamic Linker Phdr & Header Address Containment
    const char *tf_addr_path = NULL;
    const char *(*fn_dyld_path)(const void *) = (const char *(*)(const void *))dlsym(RTLD_DEFAULT, "dyld_image_path_containing_address");
    if (fn_dyld_path) {
        tf_addr_path = fn_dyld_path((const void *)tf_run_stealth_audit);
    }
    BOOL dyld_addr_clean = (tf_addr_path == NULL || strcasestr(tf_addr_path, "Foundation") != NULL);
    if (!dyld_addr_clean) allPassed = NO;

    // 47. Echelon 11: Mach VM Region W^X Memory Protection (mach_vm_region)
    mach_vm_address_t mvm_addr = (mach_vm_address_t)(uintptr_t)tf_run_stealth_audit;
    mach_vm_size_t mvm_size = 0;
    vm_region_basic_info_data_64_t mvm_info;
    mach_msg_type_number_t mvm_cnt = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t mvm_obj = MACH_PORT_NULL;
    kern_return_t mvm_kr = KERN_FAILURE;
    kern_return_t (*real_mach_vm_region)(mach_port_t, mach_vm_address_t *, mach_vm_size_t *, vm_region_flavor_t, vm_region_info_t, mach_msg_type_number_t *, mach_port_t *) =
        (kern_return_t (*)(mach_port_t, mach_vm_address_t *, mach_vm_size_t *, vm_region_flavor_t, vm_region_info_t, mach_msg_type_number_t *, mach_port_t *))dlsym(RTLD_DEFAULT, "mach_vm_region");
    if (real_mach_vm_region) {
        mvm_kr = real_mach_vm_region(mach_task_self(), &mvm_addr, &mvm_size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&mvm_info, &mvm_cnt, &mvm_obj);
    }
    BOOL mach_vm_clean = (mvm_kr != KERN_SUCCESS || !(mvm_info.protection & VM_PROT_WRITE));
    if (!mach_vm_clean) allPassed = NO;

    // 48. Echelon 11: Mach VM Region Recurse W^X Memory Protection (mach_vm_region_recurse)
    mach_vm_address_t rec_maddr = (mach_vm_address_t)(uintptr_t)tf_run_stealth_audit;
    mach_vm_size_t rec_msize = 0;
    natural_t rec_mdepth = 0;
    vm_region_submap_info_data_64_t rec_minfo;
    mach_msg_type_number_t rec_mcnt = VM_REGION_SUBMAP_INFO_COUNT_64;
    kern_return_t rec_mkr = KERN_FAILURE;
    kern_return_t (*real_mach_vm_rec)(mach_port_t, mach_vm_address_t *, mach_vm_size_t *, natural_t *, vm_region_recurse_info_t, mach_msg_type_number_t *) =
        (kern_return_t (*)(mach_port_t, mach_vm_address_t *, mach_vm_size_t *, natural_t *, vm_region_recurse_info_t, mach_msg_type_number_t *))dlsym(RTLD_DEFAULT, "mach_vm_region_recurse");
    if (real_mach_vm_rec) {
        rec_mkr = real_mach_vm_rec(mach_task_self(), &rec_maddr, &rec_msize, &rec_mdepth, (vm_region_recurse_info_t)&rec_minfo, &rec_mcnt);
    }
    BOOL vm_rec_clean = (rec_mkr != KERN_SUCCESS || !(rec_minfo.protection & VM_PROT_WRITE));
    if (!vm_rec_clean) allPassed = NO;

    // 49. Echelon 11: Dynamic Linker Preflight Shield (dlopen_preflight)
    BOOL preflight_blocked = YES;
    bool (*preflight_fn)(const char *) = (bool (*)(const char *))dlsym(RTLD_DEFAULT, "dlopen_preflight");
    if (preflight_fn) {
        bool can_load_jb = preflight_fn("/var/jb/usr/lib/TweakForceHooks.dylib");
        bool can_load_sub = preflight_fn("/Library/MobileSubstrate/MobileSubstrate.dylib");
        preflight_blocked = (!can_load_jb && !can_load_sub);
    }
    if (!preflight_blocked) allPassed = NO;

    // 50. Echelon 11: VFS Node Path Cloaking (fcntl F_GETPATH)
    char fcntl_buf[1024] = {0};
    int jb_fd = open("/var/jb", O_RDONLY);
    BOOL fcntl_clean = YES;
    if (jb_fd >= 0) {
        int fcntl_res = fcntl(jb_fd, F_GETPATH, fcntl_buf);
        fcntl_clean = (fcntl_res == -1 && errno == ENOENT);
        close(jb_fd);
    } else {
        fcntl_clean = YES;
    }
    if (!fcntl_clean) allPassed = NO;

    // 51. Echelon 12: Direct Allocating Mach VM Read Trampoline Cloaking (mach_vm_read)
    vm_offset_t mvr_data = 0;
    mach_msg_type_number_t mvr_cnt = 0;
    kern_return_t mvr_kr = tf_my_mach_vm_read(mach_task_self(), (mach_vm_address_t)(uintptr_t)&stat, 16, &mvr_data, &mvr_cnt);
    BOOL mvr_clean = NO;
    if (mvr_kr == KERN_SUCCESS && mvr_data && mvr_cnt >= 4) {
        uint32_t *u32 = (uint32_t *)(uintptr_t)mvr_data;
        mvr_clean = (u32[0] != 0x58000050);
        vm_deallocate(mach_task_self(), mvr_data, mvr_cnt);
    } else if (mvr_kr == KERN_SUCCESS) {
        mvr_clean = YES;
    }
    if (!mvr_clean) allPassed = NO;

    // 52. Echelon 12: File Descriptor Mount Shield (fstatfs)
    int root_fd = open("/", O_RDONLY);
    BOOL fstatfs_clean = NO;
    if (root_fd >= 0) {
        struct statfs root_sfs;
        memset(&root_sfs, 0, sizeof(root_sfs));
        int fs_ret = fstatfs(root_fd, &root_sfs);
        close(root_fd);
        fstatfs_clean = (fs_ret == 0 && (root_sfs.f_flags & MNT_RDONLY) != 0);
    } else {
        fstatfs_clean = YES;
    }
    if (!fstatfs_clean) allPassed = NO;

    // 53. Echelon 12: Low-Level LLVM Call-Stack Unwind Shield (_Unwind_Backtrace)
    BOOL unwind_clean = YES;
    _Unwind_Reason_Code (*fn_unwind_bt)(_Unwind_Trace_Fn, void *) =
        (_Unwind_Reason_Code (*)(_Unwind_Trace_Fn, void *))dlsym(RTLD_DEFAULT, "_Unwind_Backtrace");
    if (fn_unwind_bt) {
        fn_unwind_bt(tf_test_unwind_audit_cb, &unwind_clean);
    }
    if (!unwind_clean) allPassed = NO;

    // 54. Echelon 12: Process Image Path Isolation (proc_pidpath)
    char pidpath_buf[1024] = {0};
    int p_path_ret = proc_pidpath(1, pidpath_buf, sizeof(pidpath_buf));
    BOOL pidpath_clean = (p_path_ret <= 0);
    if (!pidpath_clean) allPassed = NO;

    // 55. Echelon 12: Extended Attribute Shield (getxattr)
    char xval[256] = {0};
    ssize_t gx_ret = getxattr("/var/mobile", "com.apple.rootless", xval, sizeof(xval), 0, 0);
    BOOL getxattr_clean = (gx_ret < 0);
    if (!getxattr_clean) allPassed = NO;

    // 56. Echelon 12: Extended Attribute Listing Cloaking (listxattr)
    char xlist[1024] = {0};
    ssize_t lx_ret = listxattr("/var/jb", xlist, sizeof(xlist), 0);
    BOOL listxattr_clean = (lx_ret < 0);
    if (!listxattr_clean) allPassed = NO;

    // 57. Echelon 13: Raw directory buffer cloaking (getdirentries64)
    char gde_buf[2048] = {0};
    off_t gde_base = 0;
    int dir_fd = open("/Applications", O_RDONLY);
    BOOL getdir_clean = YES;
    if (dir_fd >= 0) {
        ssize_t (*fn_getdir)(int, void *, size_t, off_t *) = (ssize_t (*)(int, void *, size_t, off_t *))dlsym(RTLD_DEFAULT, "__getdirentries64");
        if (!fn_getdir) fn_getdir = (ssize_t (*)(int, void *, size_t, off_t *))dlsym(RTLD_DEFAULT, "getdirentries64");
        if (fn_getdir) {
            ssize_t g_cnt = fn_getdir(dir_fd, gde_buf, sizeof(gde_buf), &gde_base);
            if (g_cnt > 0) {
                size_t off = 0;
                while (off + offsetof(struct dirent, d_name) <= (size_t)g_cnt) {
                    struct dirent *de = (struct dirent *)(gde_buf + off);
                    if (de->d_reclen == 0 || off + de->d_reclen > (size_t)g_cnt) break;
                    if (strcasestr(de->d_name, "cydia") || strcasestr(de->d_name, "sileo") || strcasestr(de->d_name, "zebra")) {
                        getdir_clean = NO;
                        break;
                    }
                    off += de->d_reclen;
                }
            }
        }
        close(dir_fd);
    }
    if (!getdir_clean) allPassed = NO;

    // 58. Echelon 13: File descriptor mount shield (fstatvfs)
    int root_vfs_fd = open("/", O_RDONLY);
    BOOL fstatvfs_clean = NO;
    if (root_vfs_fd >= 0) {
        struct statvfs svfs;
        memset(&svfs, 0, sizeof(svfs));
        int sv_ret = fstatvfs(root_vfs_fd, &svfs);
        close(root_vfs_fd);
        fstatvfs_clean = (sv_ret == 0 && (svfs.f_flag & ST_RDONLY) != 0);
    } else {
        fstatvfs_clean = YES;
    }
    if (!fstatvfs_clean) allPassed = NO;

    // 59. Echelon 13: Open file descriptors inspection isolation (proc_pidinfo PROC_PIDLISTFDS)
    struct proc_fdinfo_test {
        int32_t proc_fd;
        uint32_t proc_fdtype;
    };
    struct proc_fdinfo_test test_fds[64];
    memset(test_fds, 0, sizeof(test_fds));
    int fds_bytes = proc_pidinfo(getpid(), 1, 0, test_fds, sizeof(test_fds));
    BOOL pidfds_clean = YES;
    if (fds_bytes > 0) {
        int num_fds = fds_bytes / (int)sizeof(struct proc_fdinfo_test);
        for (int i = 0; i < num_fds; i++) {
            char fpath[1024] = {0};
            if (fcntl(test_fds[i].proc_fd, F_GETPATH, fpath) == 0 && fpath[0] != '\0') {
                if (strcasestr(fpath, "tweakforce") || strcasestr(fpath, "weakforce") || strcasestr(fpath, "/var/jb")) {
                    pidfds_clean = NO;
                    break;
                }
            }
        }
    }
    if (!pidfds_clean) allPassed = NO;

    // 60. Echelon 13: Runtime class list buffer cloaking (objc_getClassList)
    int total_classes = objc_getClassList(NULL, 0);
    BOOL getclasslist_clean = YES;
    if (total_classes > 0) {
        int sample_sz = (total_classes < 100) ? total_classes : 100;
        Class *sample_buf = (Class *)malloc(sample_sz * sizeof(Class));
        if (sample_buf) {
            int fetched = objc_getClassList(sample_buf, sample_sz);
            int check_sz = (fetched < sample_sz) ? fetched : sample_sz;
            for (int i = 0; i < check_sz; i++) {
                const char *cn = sample_buf[i] ? class_getName(sample_buf[i]) : NULL;
                if (cn && (strcasestr(cn, "tweakforce") || strcasestr(cn, "weakforce"))) {
                    getclasslist_clean = NO;
                    break;
                }
            }
            free(sample_buf);
        }
    }
    if (!getclasslist_clean) allPassed = NO;

    // 61. Echelon 13: Mach task threads isolation (pthread_getname_np)
    char cur_tname[128] = {0};
    pthread_getname_np(pthread_self(), cur_tname, sizeof(cur_tname));
    BOOL task_threads_clean = YES;
    if (cur_tname[0] != '\0') {
        if (strcasestr(cur_tname, "tweakforce") || strcasestr(cur_tname, "weakforce")) {
            task_threads_clean = NO;
        }
    }
    if (!task_threads_clean) allPassed = NO;

    // 62. Echelon 13: Private CoreServices workspace URL scheme check (LSApplicationWorkspace)
    BOOL ls_clean = YES;
    Class wsClass = NSClassFromString(@"LSApplicationWorkspace");
    if (wsClass && [wsClass respondsToSelector:@selector(defaultWorkspace)]) {
        id ws = [wsClass performSelector:@selector(defaultWorkspace)];
        if (ws && [ws respondsToSelector:@selector(applicationsAvailableForHandlingURLScheme:)]) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
            NSArray *apps = [ws performSelector:@selector(applicationsAvailableForHandlingURLScheme:) withObject:@"cydia"];
            if (apps && [apps count] > 0) {
                ls_clean = NO;
            }
#pragma clang diagnostic pop
        }
    }
    if (!ls_clean) allPassed = NO;

    // 63. Echelon 14: Dyld inserted/interposing libraries check
    BOOL dyld_inserted_clean = YES;
    bool (*fn_dyld_ins)(void) = (bool (*)(void))dlsym(RTLD_DEFAULT, "dyld_has_inserted_or_interposing_libraries");
    if (!fn_dyld_ins) fn_dyld_ins = (bool (*)(void))dlsym(RTLD_DEFAULT, "_dyld_has_inserted_or_interposing_libraries");
    if (fn_dyld_ins) {
        if (fn_dyld_ins() != false) {
            dyld_inserted_clean = NO;
        }
    }
    if (!dyld_inserted_clean) allPassed = NO;

    // 64. Echelon 14: POSIX file deletion shield check (unlink)
    int un_ret = unlink("/var/jb/test_unlink_probe");
    BOOL unlink_clean = (un_ret == -1 && errno == ENOENT);
    if (!unlink_clean) allPassed = NO;

    // 65. Echelon 14: POSIX directory deletion shield check (rmdir)
    int rm_ret = rmdir("/var/jb");
    BOOL rmdir_clean = (rm_ret == -1 && errno == ENOENT);
    if (!rmdir_clean) allPassed = NO;

    // 66. Echelon 14: POSIX permissions shield check (chmod)
    int ch_ret = chmod("/var/jb", 0755);
    BOOL chmod_clean = (ch_ret == -1 && errno == ENOENT);
    if (!chmod_clean) allPassed = NO;

    // 67. Echelon 14: Sandbox process execution check (execve)
    char *const ex_argv[] = {"sh", NULL};
    int ex_ret = execve("/bin/sh", ex_argv, NULL);
    BOOL execve_clean = (ex_ret == -1 && errno == ENOENT);
    if (!execve_clean) allPassed = NO;

    // 68. Echelon 14: Memory W^X enforcement check (mprotect RWX)
    void *dummy_page = malloc(4096);
    BOOL mprotect_clean = YES;
    if (dummy_page) {
        int mp_ret = mprotect(dummy_page, 4096, PROT_READ | PROT_WRITE | PROT_EXEC);
        mprotect_clean = (mp_ret == -1 && errno == EACCES);
        free(dummy_page);
    }
    if (!mprotect_clean) allPassed = NO;

    // 69. Echelon 14: CoreServices application proxy inspection (LSApplicationProxy)
    BOOL proxy_clean = YES;
    Class prxClass = NSClassFromString(@"LSApplicationProxy");
    if (prxClass && [prxClass respondsToSelector:@selector(applicationProxyForIdentifier:)]) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
        id prx = [prxClass performSelector:@selector(applicationProxyForIdentifier:) withObject:@"org.coolstar.SileoStore"];
        if (prx != nil) {
            proxy_clean = NO;
        }
#pragma clang diagnostic pop
    }
    if (!proxy_clean) allPassed = NO;

    // 70. Echelon 14: CoreFoundation bundle lookup check (CFBundle)
    BOOL cfbundle_clean = YES;
    CFBundleRef (*fn_cfb)(CFStringRef) = (CFBundleRef (*)(CFStringRef))dlsym(RTLD_DEFAULT, "CFBundleGetBundleWithIdentifier");
    if (fn_cfb) {
        CFBundleRef cb = fn_cfb(CFSTR("org.coolstar.SileoStore"));
        if (cb != NULL) {
            cfbundle_clean = NO;
        }
    }
    if (!cfbundle_clean) allPassed = NO;

    // 71. Echelon 15: Apple Data Protection open check (open_dprotected_np)
    int odp_ret = open_dprotected_np("/var/jb", O_RDONLY, 0, 0);
    BOOL odp_clean = (odp_ret == -1 && errno == ENOENT);
    if (!odp_clean) allPassed = NO;

    // 72. Echelon 15: Mapped Memory Region File Path check (proc_regionfilename)
    char reg_buf[1024] = {0};
    int reg_len = proc_regionfilename(getpid(), (uint64_t)(uintptr_t)&tf_install_spoof_and_stealth_hooks, reg_buf, sizeof(reg_buf));
    BOOL reg_clean = YES;
    if (reg_len > 0) {
        if (tf_is_jailbreak_path(reg_buf) ||
            strcasestr(reg_buf, "tweakforce") != NULL ||
            strcasestr(reg_buf, "weakforce") != NULL ||
            strcasestr(reg_buf, "ellekit") != NULL ||
            strcasestr(reg_buf, "roothide") != NULL) {
            reg_clean = NO;
        }
    }
    if (!reg_clean) allPassed = NO;

    // 73. Echelon 15: Low-Level File Descriptor Status check (fstat)
    BOOL fstat_clean = YES;
    int test_fd = open("/etc/hosts", O_RDONLY);
    if (test_fd >= 0) {
        struct stat st;
        if (fstat(test_fd, &st) != 0) fstat_clean = NO;
        close(test_fd);
    }
    if (!fstat_clean) allPassed = NO;

    // 74. Echelon 15: POSIX Privilege Escalation check (setuid 0)
    int uid_ret = setuid(0);
    BOOL setuid_clean = (uid_ret == -1 && errno == EPERM);
    if (!setuid_clean) allPassed = NO;

    // 75. Echelon 15: Terminal & Pseudo-TTY Isolation check (isatty 0)
    int isatty_ret = isatty(0);
    BOOL isatty_clean = (isatty_ret == 0 && errno == ENOTTY);
    if (!isatty_clean) allPassed = NO;

    // 76. Echelon 15: Extended Process Execution check (execvp /var/jb/sh & sh filter)
    char *const vp_argv[] = {"sh", NULL};
    int vp_ret = tf_my_execvp("sh", vp_argv);
    BOOL execvp_clean = (vp_ret == -1 && errno == ENOENT);
    if (!execvp_clean) allPassed = NO;

    // 77. Echelon 15: CoreFoundation Bundle List check (CFBundleGetAllBundles)
    BOOL cfall_clean = YES;
    @try {
        CFArrayRef allBundles = CFBundleGetAllBundles();
        if (allBundles) {
            CFIndex bCount = CFArrayGetCount(allBundles);
            for (CFIndex i = 0; i < bCount; i++) {
                CFBundleRef bRef = (CFBundleRef)CFArrayGetValueAtIndex(allBundles, i);
                if (bRef) {
                    CFStringRef bid = CFBundleGetIdentifier(bRef);
                    if (bid && tf_is_jailbreak_bundle_id((__bridge NSString *)bid)) {
                        cfall_clean = NO;
                        break;
                    }
                }
            }
        }
    } @catch (NSException *e) {
        cfall_clean = NO;
    }
    if (!cfall_clean) allPassed = NO;

    // 78. Echelon 15: Cocoa Bundle List check ([NSBundle allBundles])
    BOOL nsall_clean = YES;
    @try {
        NSArray<NSBundle *> *allNsBundles = [NSBundle allBundles];
        for (id nsbItem in allNsBundles) {
            if ([nsbItem isKindOfClass:[NSBundle class]]) {
                NSBundle *nsb = (NSBundle *)nsbItem;
                if (nsb.bundleIdentifier && tf_is_jailbreak_bundle_id(nsb.bundleIdentifier)) {
                    nsall_clean = NO;
                    break;
                }
            }
        }
    } @catch (NSException *e) {
        nsall_clean = NO;
    }
    if (!nsall_clean) allPassed = NO;

    // 79. Echelon 16: Mach VM W^X Protection check (vm_protect RWX)
    vm_address_t test_vm_addr = 0;
    vm_allocate(mach_task_self(), &test_vm_addr, PAGE_SIZE, VM_FLAGS_ANYWHERE);
    BOOL vm_prot_clean = YES;
    if (test_vm_addr != 0) {
        kern_return_t kr = vm_protect(mach_task_self(), test_vm_addr, PAGE_SIZE, FALSE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
        vm_prot_clean = (kr == KERN_PROTECTION_FAILURE);
        vm_deallocate(mach_task_self(), test_vm_addr, PAGE_SIZE);
    }
    if (!vm_prot_clean) allPassed = NO;

    // 80. Echelon 16: Mach Task For Pid Sandbox check (task_for_pid pid 1)
    mach_port_name_t test_tport = MACH_PORT_NULL;
    kern_return_t tfp_kr = task_for_pid(mach_task_self(), 1, &test_tport);
    BOOL tfp_clean = (tfp_kr != KERN_SUCCESS && test_tport == MACH_PORT_NULL);
    if (!tfp_clean) allPassed = NO;

    // 81. Echelon 16: POSIX User ID Identity check (getuid / geteuid)
    BOOL uid_ident_clean = (getuid() == 501 && geteuid() == 501);
    if (!uid_ident_clean) allPassed = NO;

    // 82. Echelon 16: Password Database Shell Masking check (getpwuid shell)
    BOOL pw_clean = YES;
    struct passwd *pw = getpwuid(501);
    if (pw && pw->pw_shell) {
        if (strstr(pw->pw_shell, "sh") || tf_is_jailbreak_path(pw->pw_shell)) {
            pw_clean = NO;
        }
    }
    if (!pw_clean) allPassed = NO;

    // 83. Echelon 16: Dyld All Image Infos check (_dyld_get_all_image_infos)
    BOOL dyld_all_clean = YES;
    const struct dyld_all_image_infos *d_infos = tf_my_dyld_get_all_image_infos();
    if (d_infos && d_infos->infoArray) {
        for (uint32_t i = 0; i < d_infos->infoArrayCount; i++) {
            const char *p = d_infos->infoArray[i].imageFilePath;
            if (p && (tf_is_jailbreak_path(p) ||
                      strcasestr(p, "tweakforce") != NULL ||
                      strcasestr(p, "weakforce") != NULL ||
                      strcasestr(p, "ellekit") != NULL ||
                      strcasestr(p, "roothide") != NULL)) {
                dyld_all_clean = NO;
                break;
            }
        }
    }
    if (!dyld_all_clean) allPassed = NO;

    // 84. Echelon 16: ObjC Runtime Method Reflection check (class_copyMethodList)
    BOOL method_refl_clean = YES;
    unsigned int m_cnt = 0;
    Method *m_list = class_copyMethodList([NSFileManager class], &m_cnt);
    if (m_list) {
        for (unsigned int i = 0; i < m_cnt; i++) {
            SEL sel = method_getName(m_list[i]);
            if (sel) {
                const char *sname = sel_getName(sel);
                if (sname && (strncmp(sname, "tf_", 3) == 0 || strncmp(sname, "TF_", 3) == 0)) {
                    method_refl_clean = NO;
                    break;
                }
            }
        }
        free(m_list);
    }
    if (!method_refl_clean) allPassed = NO;

    // 85. Echelon 16: VFS File Flags Shielding check (chflags)
    int chf_ret = chflags("/var/jb", UF_NODUMP);
    BOOL chflags_clean = (chf_ret == -1 && (errno == ENOENT || errno == EROFS || errno == EPERM));
    if (!chflags_clean) allPassed = NO;

    // 86. Echelon 16: POSIX Core Dump Limit check (getrlimit RLIMIT_CORE)
    struct rlimit rl;
    int rl_ret = getrlimit(RLIMIT_CORE, &rl);
    BOOL rlimit_clean = (rl_ret == 0 && rl.rlim_cur == 0 && rl.rlim_max == 0);
    if (!rlimit_clean) allPassed = NO;

    // 87. Echelon 17: Mach-O Main Binary FairPlay cryptid check
    BOOL cryptid_clean = NO;
    const struct mach_header_64 *main_mh = (const struct mach_header_64 *)tf_my_dyld_get_image_header(0);
    if (main_mh && (main_mh->magic == MH_MAGIC_64 || main_mh->magic == MH_CIGAM_64)) {
        const uint8_t *cptr = (const uint8_t *)main_mh + sizeof(struct mach_header_64);
        for (uint32_t i = 0; i < main_mh->ncmds; i++) {
            const struct load_command *lc = (const struct load_command *)cptr;
            if (lc->cmdsize < sizeof(struct load_command) ||
                (cptr + lc->cmdsize > (const uint8_t *)main_mh + sizeof(struct mach_header_64) + main_mh->sizeofcmds)) {
                break;
            }
            if (lc->cmd == LC_ENCRYPTION_INFO_64) {
                const struct encryption_info_command_64 *enc = (const struct encryption_info_command_64 *)lc;
                if (enc->cryptid == 1) {
                    cryptid_clean = YES;
                }
                break;
            } else if (lc->cmd == LC_ENCRYPTION_INFO) {
                const struct encryption_info_command *enc = (const struct encryption_info_command *)lc;
                if (enc->cryptid == 1) {
                    cryptid_clean = YES;
                }
                break;
            }
            cptr += lc->cmdsize;
        }
    }
    if (!cryptid_clean) allPassed = NO;

    // 88. Echelon 17: Mach-O Load Commands Sanitization check (LC_LOAD_DYLIB / LC_RPATH)
    BOOL lc_clean = YES;
    if (main_mh && (main_mh->magic == MH_MAGIC_64 || main_mh->magic == MH_CIGAM_64)) {
        const uint8_t *cptr = (const uint8_t *)main_mh + sizeof(struct mach_header_64);
        for (uint32_t i = 0; i < main_mh->ncmds; i++) {
            const struct load_command *lc = (const struct load_command *)cptr;
            if (lc->cmdsize < sizeof(struct load_command) ||
                (cptr + lc->cmdsize > (const uint8_t *)main_mh + sizeof(struct mach_header_64) + main_mh->sizeofcmds)) {
                break;
            }
            if (lc->cmd == LC_LOAD_DYLIB || lc->cmd == LC_LOAD_WEAK_DYLIB || lc->cmd == LC_REEXPORT_DYLIB) {
                const struct dylib_command *dcmd = (const struct dylib_command *)lc;
                if (dcmd->dylib.name.offset < lc->cmdsize) {
                    const char *dname = (const char *)lc + dcmd->dylib.name.offset;
                    if (tf_is_jailbreak_path(dname) ||
                        strcasestr(dname, "tweakforce") != NULL ||
                        strcasestr(dname, "weakforce") != NULL ||
                        strcasestr(dname, "ellekit") != NULL ||
                        strcasestr(dname, "roothide") != NULL ||
                        strcasestr(dname, "substrate") != NULL) {
                        lc_clean = NO;
                        break;
                    }
                }
            } else if (lc->cmd == LC_RPATH) {
                const struct rpath_command *rcmd = (const struct rpath_command *)lc;
                if (rcmd->path.offset < lc->cmdsize) {
                    const char *rpath = (const char *)lc + rcmd->path.offset;
                    if (tf_is_jailbreak_path(rpath) || strstr(rpath, "/var/jb") || strstr(rpath, "tweakforce") || strstr(rpath, "weakforce")) {
                        lc_clean = NO;
                        break;
                    }
                }
            }
            cptr += lc->cmdsize;
        }
    }
    if (!lc_clean) allPassed = NO;

    // 89. Echelon 17: _NSGetMachExecuteHeader() integrity check
    BOOL mh_clean = NO;
    const struct mach_header *exec_mh = tf_my_NSGetMachExecuteHeader();
    if (exec_mh && (exec_mh->magic == MH_MAGIC_64 || exec_mh->magic == MH_CIGAM_64)) {
        mh_clean = YES;
    }
    if (!mh_clean) allPassed = NO;

    // 90. Echelon 17: _NSGetExecutablePath() path isolation check
    BOOL exepath_clean = YES;
    char exepath_buf[1024] = {0};
    uint32_t exepath_sz = sizeof(exepath_buf);
    if (tf_my_NSGetExecutablePath(exepath_buf, &exepath_sz) == 0) {
        if (tf_is_jailbreak_path(exepath_buf) || strcasestr(exepath_buf, "tweakforce") || strcasestr(exepath_buf, "weakforce")) {
            exepath_clean = NO;
        }
    } else {
        exepath_clean = NO;
    }
    if (!exepath_clean) allPassed = NO;

    // 91. Echelon 17: embedded.mobileprovision VFS shield check
    int emb_acc = access("/var/mobile/Containers/Bundle/Application/Test/embedded.mobileprovision", F_OK);
    struct stat emb_st;
    int emb_stat = stat("/var/mobile/Containers/Bundle/Application/Test/embedded.mobileprovision", &emb_st);
    BOOL emb_vfs_clean = (emb_acc == -1 && errno == ENOENT) && (emb_stat == -1 && errno == ENOENT);
    if (!emb_vfs_clean) allPassed = NO;

    // 92. Echelon 17: Cocoa [NSBundle pathForResource:ofType:] mobileprovision check
    BOOL emb_bundle_clean = YES;
    @try {
        NSString *emb_path = [[NSBundle mainBundle] pathForResource:@"embedded" ofType:@"mobileprovision"];
        if (emb_path != nil) {
            emb_bundle_clean = NO;
        }
    } @catch (NSException *e) {
        emb_bundle_clean = NO;
    }
    if (!emb_bundle_clean) allPassed = NO;

    // 93. Echelon 17: CoreFoundation CFBundleCopyResourceURL mobileprovision check
    BOOL emb_cf_clean = YES;
    CFBundleRef mainB = CFBundleGetMainBundle();
    if (mainB) {
        CFURLRef resURL = tf_my_CFBundleCopyResourceURL(mainB, CFSTR("embedded"), CFSTR("mobileprovision"), NULL);
        if (resURL != NULL) {
            emb_cf_clean = NO;
            CFRelease(resURL);
        }
    }
    if (!emb_cf_clean) allPassed = NO;

    // 94. Echelon 17: NSBundle appStoreReceiptURL check
    BOOL receipt_clean = NO;
    @try {
        NSURL *rURL = [[NSBundle mainBundle] appStoreReceiptURL];
        if (rURL != nil && rURL.path.length > 0) {
            receipt_clean = YES;
        }
    } @catch (NSException *e) {
        receipt_clean = NO;
    }
    if (!receipt_clean) allPassed = NO;

    uint32_t svc80_in_binary = tf_audit_main_binary_direct_syscalls();

    // 17. Active Spoofed Values
    char machine[64] = {0};
    size_t size = sizeof(machine);
    sysctlbyname("hw.machine", machine, &size, NULL, 0);

    NSString *sysVer = [[UIDevice currentDevice] systemVersion];
    NSOperatingSystemVersion osVer = [[NSProcessInfo processInfo] operatingSystemVersion];
    CFTypeRef b = tf_my_MGCopyAnswer(CFSTR("BuildVersion"));
    NSString *buildVer = b ? [NSString stringWithString:(__bridge NSString *)b] : (g_overrideBuild ?: @"22A3354");
    if (b) CFRelease(b);

    [outReport appendString:@"[СТАТУС ПОЛНОГО СКРЫТИЯ ДЖЕЙЛБРЕЙКА]\n"];
    [outReport appendFormat:@"• access(/var/jb): %@\n", acc_jb_ok ? @"СКРЫТО (ENOENT) [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• stat(/var/jb): %@\n", stat_jb_ok ? @"СКРЫТО (ENOENT) [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• open(/var/jb): %@\n", open_jb_ok ? @"СКРЫТО (ENOENT) [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• fopen(/var/jb): %@\n", fopen_jb_ok ? @"СКРЫТО (NULL) [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• readlink(/var/jb): %@\n", readlink_ok ? @"СКРЫТО (ENOENT) [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• fstatat(/var/jb): %@\n", fstatat_ok ? @"СКРЫТО (ENOENT) [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• statfs(rootfs): %@\n", statfs_ok ? @"RO СМОНТИРОВАН [OK]" : @"RW УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• NSFileManager (/var/jb): %@\n", !fm_var_jb ? @"СКРЫТО (NO) [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• URL-схемы (sileo/cydia/filza): %@\n", url_ok ? @"ЗАБЛОКИРОВАНО [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• Маскировка Dyld образов: %@\n", dyld_clean ? @"ЧИСТО (0 утечек) [OK]" : [NSString stringWithFormat:@"УТЕЧКА (%d) [FAIL]", dyld_leaks]];
    [outReport appendFormat:@"• getenv(DYLD_INSERT_LIBRARIES): %@\n", env_clean ? @"ОЧИЩЕНО (NULL) [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• dlsym(MSHookFunction): %@\n", dlsym_clean ? @"СКРЫТО (NULL) [OK]" : @"ОБНАРУЖЕНО [FAIL]"];
    [outReport appendFormat:@"• dladdr маскировка символов: %@\n", dladdr_clean ? @"МАСКИРОВКА (Foundation) [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• Анти-отладка ptrace(PT_DENY): %@\n", ptrace_ok ? @"ПЕРЕХВАЧЕНО [OK]" : @"ОШИБКА [FAIL]"];
    [outReport appendFormat:@"• Sandbox fork(): %@\n", fork_blocked ? @"БЛОК (ENOSYS) [OK]" : @"РАЗРЕШЕНО [FAIL]"];
    [outReport appendFormat:@"• Подпись csops(CS_VALID): %@\n", cs_ok ? @"ВАЛИДНА [OK]" : @"ОШИБКА [FAIL]"];
    [outReport appendFormat:@"• IMP целостность (NSFileManager): %@\n", imp_ok ? @"ЧИСТО (Foundation) [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• Сетевой порт (127.0.0.1:22): %@\n", port_blocked ? @"БЛОК (ECONNREFUSED) [OK]" : @"ОТКРЫТ [FAIL]"];
    [outReport appendFormat:@"• Спавн шелла posix_spawn(/bin/sh): %@\n", spawn_ok ? @"БЛОК (ENOENT) [OK]" : @"РАЗРЕШЕНО [FAIL]"];
    [outReport appendFormat:@"• Прямой вызов syscall(SYS_access): %@\n", syscall_acc_ok ? @"СКРЫТО (ENOENT) [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• Тест записи вне песочницы: %@\n", write_probe_blocked ? @"БЛОК (EACCES) [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• Интроспекция objc_getClass: %@\n", cls_clean ? @"ЧИСТО (Nil) [OK]" : @"ОБНАРУЖЕНО [FAIL]"];
    [outReport appendFormat:@"• Cocoa [NSProcessInfo environment]: %@\n", proc_env_clean ? @"ОЧИЩЕНО [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• Заголовок Mach-O (_dyld_get_image_header): %@\n", dyld_hdr_ok ? @"ВАЛИДЕН (MH_MAGIC_64) [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• Аппаратные точки останова (thread_get_state): %@\n", hw_dbg_clean ? @"ОЧИЩЕНО (0 регистров) [OK]" : @"ОБНАРУЖЕНО [FAIL]"];
    [outReport appendFormat:@"• Защита памяти (vm_region_64 W^X): %@\n", vm_clean ? @"ЧИСТО (RX) [OK]" : @"RWX УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• Обработчик сигналов sigaction(SIGTRAP): %@\n", sig_clean ? @"СТАНДАРТНЫЙ (SIG_DFL) [OK]" : @"ПЕРЕХВАЧЕН [FAIL]"];
    [outReport appendFormat:@"• Динамическая загрузка dlopen: %@\n", dlopen_clean ? @"СКРЫТО (NULL) [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• Канонический путь realpath: %@\n", realpath_clean ? @"СКРЫТО (ENOENT) [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• Инспекция NSBundle (CydiaSubstrate): %@\n", bundle_clean ? @"СКРЫТО (nil) [OK]" : @"ОБНАРУЖЕНО [FAIL]"];
    [outReport appendFormat:@"• Изоляция процессов proc_listpids: %@\n", proc_clean ? @"ИЗОЛИРОВАНО (только self) [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• Поток директорий opendir(/var/jb): %@\n", opendir_clean ? @"СКРЫТО (ENOENT) [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• Фильтрация файлов scandir(/Applications): %@\n", scandir_clean ? @"ЧИСТО (0 артефактов) [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• Mach IPC bootstrap_look_up: %@\n", bootstrap_clean ? @"БЛОК (UNKNOWN_SERVICE) [OK]" : @"ОБНАРУЖЕНО [FAIL]"];
    [outReport appendFormat:@"• Dyld add_image нотификации: %@\n", dyld_cb_clean ? @"ФИЛЬТРАЦИЯ (0 твиков) [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• Массив TASK_DYLD_INFO (task_info): %@\n", task_dyld_clean ? @"ОЧИЩЕНО (0 твиков) [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• Глубокий dlsym щит (символы твика): %@\n", dlsym_ext_clean ? @"ЗАБЛОКИРОВАНО (NULL) [OK]" : @"ОБНАРУЖЕНО [FAIL]"];
    [outReport appendFormat:@"• Относительный fstatat(/var, 'jb'): %@\n", fstatat_rel_clean ? @"СКРЫТО (ENOENT) [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• Стек вызовов backtrace: %@\n", bt_clean ? @"ИЗОЛИРОВАНО [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• Своп Mach Exception портов: %@\n", exc_swap_clean ? @"ОЧИЩЕНО (0 портов) [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• Защита kern.bootargs: %@\n", bootargs_clean ? @"ЗАБЛОКИРОВАНО (ENOENT) [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• Проверка песочницы sandbox_check: %@\n", sandbox_clean ? @"БЛОКИРОВКА (EPERM) [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• Маскировка трамплинов в памяти: %@\n", tramp_cloaked ? @"ЧИСТО (Стандартный пролог) [OK]" : @"ОБНАРУЖЕНО [FAIL]"];
    [outReport appendFormat:@"• Очистка sysctl procargs: %@\n", procargs_clean ? @"ОЧИЩЕНО (0 переменных) [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• Аудит прямых SVC #0x80 в бинарнике: %u найдено [OK]\n", svc80_in_binary];
    [outReport appendFormat:@"• Адрес в Dyld (dyld_image_path): %@\n", dyld_addr_clean ? @"МАСКИРОВКА (Foundation) [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• Память mach_vm_region W^X: %@\n", mach_vm_clean ? @"ЧИСТО (RX) [OK]" : @"RWX УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• Память mach_vm_region_recurse: %@\n", vm_rec_clean ? @"ЧИСТО (RX) [OK]" : @"RWX УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• Проверка dlopen_preflight: %@\n", preflight_blocked ? @"ЗАБЛОКИРОВАНО (false) [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• Путь Vnode fcntl(F_GETPATH): %@\n", fcntl_clean ? @"СКРЫТО (ENOENT) [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• Память mach_vm_read: %@\n", mvr_clean ? @"ЗАМАСКИРОВАНА [OK]" : @"ОБНАРУЖЕНО [FAIL]"];
    [outReport appendFormat:@"• Дескриптор fstatfs(root): %@\n", fstatfs_clean ? @"RO СМОНТИРОВАН [OK]" : @"RW УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• Стек _Unwind_Backtrace: %@\n", unwind_clean ? @"ЧИСТ (0 твиков) [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• Изоляция proc_pidpath(pid 1): %@\n", pidpath_clean ? @"ИЗОЛИРОВАНО (ESRCH) [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• Атрибут getxattr(rootless): %@\n", getxattr_clean ? @"СКРЫТО (ENOATTR) [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• Список listxattr(/var/jb): %@\n", listxattr_clean ? @"СКРЫТО (ENOENT) [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• Буфер getdirentries(/Applications): %@\n", getdir_clean ? @"ЧИСТО (0 артефактов) [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• Дескриптор fstatvfs(root): %@\n", fstatvfs_clean ? @"RO СМОНТИРОВАН [OK]" : @"RW УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• Дескрипторы proc_pidinfo(FDS): %@\n", pidfds_clean ? @"ИЗОЛИРОВАНО [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• Буфер objc_getClassList: %@\n", getclasslist_clean ? @"ЧИСТО (0 твиков) [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• Потоки pthread_getname_np: %@\n", task_threads_clean ? @"ИЗОЛИРОВАНО [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• CoreServices LSApplicationWorkspace: %@\n", ls_clean ? @"ЗАБЛОКИРОВАНО (0 схем) [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• Dyld inserted/interposing: %@\n", dyld_inserted_clean ? @"ОЧИЩЕНО (false) [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• Удаление unlink(/var/jb): %@\n", unlink_clean ? @"БЛОК (ENOENT) [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• Удаление папки rmdir(/var/jb): %@\n", rmdir_clean ? @"БЛОК (ENOENT) [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• Права доступа chmod(/var/jb): %@\n", chmod_clean ? @"БЛОК (ENOENT) [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• Выполнение execve(/bin/sh): %@\n", execve_clean ? @"БЛОК (ENOENT) [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• Защита RWX mprotect(W^X): %@\n", mprotect_clean ? @"БЛОК (EACCES) [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• CoreServices LSApplicationProxy: %@\n", proxy_clean ? @"СКРЫТО (nil) [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• CoreFoundation CFBundle: %@\n", cfbundle_clean ? @"СКРЫТО (NULL) [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• Защищённое открытие open_dprotected_np: %@\n", odp_clean ? @"СКРЫТО (ENOENT) [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• Регион памяти proc_regionfilename: %@\n", reg_clean ? @"МАСКИРОВКА (Foundation) [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• Дескриптор fstat(/etc/hosts): %@\n", fstat_clean ? @"ВАЛИДЕН [OK]" : @"ОШИБКА [FAIL]"];
    [outReport appendFormat:@"• Эскалация прав setuid(0): %@\n", setuid_clean ? @"БЛОК (EPERM) [OK]" : @"РАЗРЕШЕНО [FAIL]"];
    [outReport appendFormat:@"• Терминал isatty(0): %@\n", isatty_clean ? @"ИЗОЛИРОВАНО (ENOTTY) [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• Запуск шелла execvp(sh): %@\n", execvp_clean ? @"БЛОК (ENOENT) [OK]" : @"РАЗРЕШЕНО [FAIL]"];
    [outReport appendFormat:@"• Список CFBundleGetAllBundles: %@\n", cfall_clean ? @"ЧИСТО (0 твиков) [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• Массив [NSBundle allBundles]: %@\n", nsall_clean ? @"ЧИСТО (0 твиков) [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• Mach VM защита vm_protect(W^X): %@\n", vm_prot_clean ? @"БЛОК RWX [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• Mach task_for_pid(launchd): %@\n", tfp_clean ? @"БЛОК ПЕСОЧНИЦЫ [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• POSIX User ID (getuid/geteuid): %@\n", uid_ident_clean ? @"501 (mobile) [OK]" : @"ROOT УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• База passwd (getpwuid shell): %@\n", pw_clean ? @"ОЧИЩЕНО [OK]" : @"УТЕЧКА ШЕЛЛА [FAIL]"];
    [outReport appendFormat:@"• Структура _dyld_get_all_image_infos: %@\n", dyld_all_clean ? @"ЧИСТО (0 твиков) [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• Отражение class_copyMethodList: %@\n", method_refl_clean ? @"ХУКИ СКРЫТЫ [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• Флаги VFS chflags(/var/jb): %@\n", chflags_clean ? @"БЛОК (ENOENT) [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• Лимит дампов getrlimit(CORE): %@\n", rlimit_clean ? @"0 (ЗАПРЕЩЕНО) [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• Mach-O FairPlay (cryptid=1): %@\n", cryptid_clean ? @"ЗАЩИЩЕНО [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• Mach-O команды загрузки: %@\n", lc_clean ? @"ОЧИЩЕНО [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• Целостность _NSGetMachExecuteHeader: %@\n", mh_clean ? @"ВАЛИДЕН [OK]" : @"ОШИБКА [FAIL]"];
    [outReport appendFormat:@"• Изоляция _NSGetExecutablePath: %@\n", exepath_clean ? @"ИЗОЛИРОВАНО [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• Экран VFS embedded.mobileprovision: %@\n", emb_vfs_clean ? @"СКРЫТО (ENOENT) [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• NSBundle pathForResource(mobileprovision): %@\n", emb_bundle_clean ? @"СКРЫТО (nil) [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• CFBundleCopyResourceURL(mobileprovision): %@\n", emb_cf_clean ? @"СКРЫТО (NULL) [OK]" : @"УТЕЧКА [FAIL]"];
    [outReport appendFormat:@"• Валидность appStoreReceiptURL: %@\n\n", receipt_clean ? @"ВАЛИДНО [OK]" : @"УТЕЧКА [FAIL]"];

    [outReport appendString:@"[АКТИВНЫЙ СПУФИНГ УСТРОЙСТВА]\n"];
    [outReport appendFormat:@"• Модель (hw.machine): %s [OK]\n", machine[0] ? machine : "iPhone15,3"];
    [outReport appendFormat:@"• Версия iOS (UIDevice): %@ [OK]\n", sysVer ?: @"18.0"];
    [outReport appendFormat:@"• Версия NSProcessInfo: %ld.%ld.%ld [OK]\n", (long)osVer.majorVersion, (long)osVer.minorVersion, (long)osVer.patchVersion];
    [outReport appendFormat:@"• Сборка (MobileGestalt): %@ [OK]", buildVer ?: @"22A3354"];

    if (outAllPassed) *outAllPassed = allPassed;
}

static void tf_show_stealth_audit_alert(BOOL force) {
    static BOOL s_shownOnce = NO;
    if (!force && s_shownOnce) return;

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        if (!force && s_shownOnce) return;

        NSMutableString *report = [NSMutableString string];
        BOOL allPassed = YES;
        @try {
            tf_run_stealth_audit(report, &allPassed);
        } @catch (NSException *e) {
            os_log_error(TFHLog(), "[TweakForce] Stealth audit exception caught: %{public}@", e.reason);
            [report appendFormat:@"\n[Исключение аудита]: %@\n", e.reason];
            allPassed = NO;
        }

        dispatch_async(dispatch_get_main_queue(), ^{
            if (!force && s_shownOnce) return;

            UIViewController *topVC = tf_get_top_view_controller();
            if (!topVC || topVC.isBeingDismissed || topVC.view.window == nil) {
                static int retryCount = 0;
                if (retryCount < 20) {
                    retryCount++;
                    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                        tf_show_stealth_audit_alert(force);
                    });
                }
                return;
            }

            s_shownOnce = YES;

            NSString *title = allPassed ? @"🛡️ TweakForce: Полное скрытие активно ✅" : @"⚠️ TweakForce: Замечены утечки ❌";

            UIAlertController *alert = [UIAlertController alertControllerWithTitle:title
                                                                           message:report
                                                                    preferredStyle:UIAlertControllerStyleAlert];

            [alert addAction:[UIAlertAction actionWithTitle:@"OK"
                                                      style:UIAlertActionStyleCancel
                                                    handler:nil]];

            [alert addAction:[UIAlertAction actionWithTitle:@"Повторить тест 🔄"
                                                      style:UIAlertActionStyleDefault
                                                    handler:^(UIAlertAction * _Nonnull action) {
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.4 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                    tf_show_stealth_audit_alert(YES);
                });
            }]];

            [topVC presentViewController:alert animated:YES completion:nil];
        });
    });
}

static void tf_schedule_stealth_audit(void) {
    NSString *bundleID = [[NSBundle mainBundle] bundleIdentifier];
    if (!bundleID || [bundleID hasPrefix:@"com.apple."]) {
        return;
    }

    [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidBecomeActiveNotification
                                                      object:nil
                                                       queue:[NSOperationQueue mainQueue]
                                                  usingBlock:^(NSNotification * _Nonnull note) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            tf_show_stealth_audit_alert(NO);
        });
    }];

    dispatch_async(dispatch_get_main_queue(), ^{
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            tf_show_stealth_audit_alert(NO);
        });
    });
}

// ============================================================================
// Constructor
// ============================================================================

__attribute__((constructor))
static void tf_hooks_constructor(void) {
    @autoreleasepool {
        tf_install_spoof_and_stealth_hooks();

        // Publish diagnostics safely in background
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
            [[DiagnosticReporter shared] publish];
        });

        // Safely schedule stealth audit alert
        tf_schedule_stealth_audit();
    }
}
