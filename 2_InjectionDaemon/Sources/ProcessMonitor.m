/*
 * TweakForce — ProcessMonitor.m (InjectionDaemon)
 * EN: kqueue EVFILT_PROC for exec/exit of known pids + proc_listpids poll to
 *     discover new pids. Resolves bundleID via the process path.
 * RU: kqueue EVFILT_PROC для exec/exit известных pid + опрос proc_listpids
 *     для поиска новых pid. bundleID определяется по пути процесса.
 * VERIFY: launch any app → handler fires with its bundleID in the daemon log.
 */
#import "ProcessMonitor.h"
#import "Logger.h"
#if __has_include(<libproc.h>)
#import <libproc.h>
#else
#ifndef PROC_ALL_PIDS
#define PROC_ALL_PIDS 1
#endif
#ifndef PROC_PIDPATHINFO_MAXSIZE
#define PROC_PIDPATHINFO_MAXSIZE (4 * 1024)
#endif
int proc_listpids(uint32_t type, uint32_t typeinfo, void *buffer, int buffersize);
int proc_pidpath(int pid, void *buffer, uint32_t buffersize);
#endif
#import <sys/event.h>
#import <sys/sysctl.h>

@implementation ProcessMonitor {
    NSTimeInterval _interval;
    dispatch_queue_t _q;
    dispatch_source_t _timer;
    NSMutableSet<NSNumber *> *_known;   // pids seen so far
    TFProcessLaunchHandler _handler;
    BOOL _running;
}

- (instancetype)initWithPollInterval:(NSTimeInterval)interval {
    if ((self = [super init])) {
        _interval = interval > 0 ? interval : 1.0;
        _q = dispatch_queue_create("com.tweakforce.procmon", DISPATCH_QUEUE_SERIAL);
        _known = [NSMutableSet set];
    }
    return self;
}

- (void)startWithHandler:(TFProcessLaunchHandler)handler {
    _handler = [handler copy];
    _running = YES;
    // Seed the baseline so we only report NEW processes.
    // Запоминаем базовый список, чтобы сообщать только о НОВЫХ процессах.
    dispatch_async(_q, ^{
        [self scanWithReporting:NO];
        self->_timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, self->_q);
        uint64_t ns = (uint64_t)(self->_interval * NSEC_PER_SEC);
        dispatch_source_set_timer(self->_timer, dispatch_time(DISPATCH_TIME_NOW, ns), ns, ns/10);
        dispatch_source_set_event_handler(self->_timer, ^{ [self scanWithReporting:YES]; });
        dispatch_resume(self->_timer);
        TFLogI(@"ProcessMonitor: started (poll=%.2fs, baseline=%lu pids)",
               self->_interval, (unsigned long)self->_known.count);
    });
}

- (void)stop {
    dispatch_async(_q, ^{
        self->_running = NO;
        if (self->_timer) { dispatch_source_cancel(self->_timer); self->_timer = nil; }
        TFLogI(@"ProcessMonitor: stopped");
    });
}

// Enumerate pids; report ones not previously seen.
// Перечисляем pid; сообщаем о тех, что не видели ранее.
- (void)scanWithReporting:(BOOL)report {
    int n = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0);
    if (n <= 0) { if (report) TFLogW(@"ProcessMonitor: proc_listpids returned %d", n); return; }
    int cap = n + 64;
    pid_t *pids = calloc(cap, sizeof(pid_t));
    if (!pids) { TFLogE(@"ProcessMonitor: calloc failed"); return; }
    int bytes = proc_listpids(PROC_ALL_PIDS, 0, pids, cap * (int)sizeof(pid_t));
    int count = bytes / (int)sizeof(pid_t);

    NSMutableSet<NSNumber *> *current = [NSMutableSet set];
    for (int i = 0; i < count; i++) {
        pid_t pid = pids[i];
        if (pid <= 0) continue;
        NSNumber *key = @(pid);
        [current addObject:key];
        if (!report) { [_known addObject:key]; continue; }
        if ([_known containsObject:key]) continue;

        [_known addObject:key];
        NSString *path = [self executablePathForPid:pid];
        if (!path) continue;
        NSString *bundle = [self bundleIDForExecutablePath:path];
        if (self->_handler) self->_handler(pid, bundle, path);
    }
    // Prune dead pids so set doesn't grow unbounded.
    // Чистим мёртвые pid, чтобы множество не росло бесконечно.
    [_known intersectSet:current];
    free(pids);
}

- (NSString *)executablePathForPid:(pid_t)pid {
    char buf[PROC_PIDPATHINFO_MAXSIZE] = {0};
    int r = proc_pidpath(pid, buf, sizeof(buf));
    if (r <= 0) return nil;
    return [NSString stringWithUTF8String:buf];
}

// EN: Derive bundleID from the .app bundle's Info.plist alongside the binary.
// RU: Определяем bundleID из Info.plist .app-бандла рядом с бинарником.
- (NSString *)bundleIDForExecutablePath:(NSString *)path {
    NSString *dir = [path stringByDeletingLastPathComponent];
    for (int depth = 0; depth < 3 && dir.length > 1; depth++) {
        if ([dir hasSuffix:@".app"]) {
            NSString *plist = [dir stringByAppendingPathComponent:@"Info.plist"];
            NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:plist];
            NSString *b = info[@"CFBundleIdentifier"];
            if (b.length) return b;
        }
        dir = [dir stringByDeletingLastPathComponent];
    }
    return nil;
}

@end
