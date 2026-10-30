/*
 * ============================================================================
 *  TweakForce — Logger.m  (InjectionDaemon)
 * ============================================================================
 *  EN: Implementation. Serial dispatch queue guards file writes.
 *  RU: Реализация. Последовательная очередь защищает запись в файл.
 *
 *  VERIFY: tail -f <log_path> while the daemon runs.
 * ============================================================================
 */
#import "Logger.h"
#import <os/log.h>

#define TF_SUBSYSTEM "com.tweakforce"
#define TF_CATEGORY  "daemon"
#define TF_LOG_MAX_BYTES (512 * 1024)   // rotate when file exceeds 512 KB

@implementation Logger {
    dispatch_queue_t _q;
    NSString *_path;
    os_log_t _oslog;
}

+ (instancetype)shared {
    static Logger *s; static dispatch_once_t once;
    dispatch_once(&once, ^{ s = [[Logger alloc] init]; });
    return s;
}

- (instancetype)init {
    if ((self = [super init])) {
        _q = dispatch_queue_create("com.tweakforce.logger", DISPATCH_QUEUE_SERIAL);
        _oslog = os_log_create(TF_SUBSYSTEM, TF_CATEGORY);
    }
    return self;
}

- (void)setLogFilePath:(NSString *)path {
    dispatch_async(_q, ^{
        self->_path = [path copy];
        NSString *dir = [path stringByDeletingLastPathComponent];
        NSError *err = nil;
        if (![NSFileManager.defaultManager createDirectoryAtPath:dir
                                     withIntermediateDirectories:YES
                                                      attributes:nil error:&err]) {
            os_log_error(self->_oslog, "[TweakForce] cannot create log dir %{public}@: %{public}@", dir, err);
        }
        if (![NSFileManager.defaultManager fileExistsAtPath:path]) {
            [NSFileManager.defaultManager createFileAtPath:path contents:nil attributes:nil];
        }
    });
}

static const char *levelName(TFLogLevel l) {
    switch (l) {
        case TFLogLevelDebug: return "DEBUG";
        case TFLogLevelInfo:  return "INFO";
        case TFLogLevelWarn:  return "WARN";
        case TFLogLevelError: return "ERROR";
    }
    return "?";
}

- (void)log:(TFLogLevel)level format:(NSString *)format, ... {
    va_list args; va_start(args, format);
    NSString *msg = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);

    // os_log (always) / os_log (всегда)
    switch (level) {
        case TFLogLevelError: os_log_error(_oslog, "%{public}s", msg.UTF8String); break;
        case TFLogLevelWarn:  os_log(_oslog, "[WARN] %{public}s", msg.UTF8String); break;
        default:              os_log(_oslog, "%{public}s", msg.UTF8String); break;
    }

    // File (async) / Файл (асинхронно)
    dispatch_async(_q, ^{
        if (!self->_path) return;
        NSDate *now = [NSDate date];
        NSDateFormatter *df = [[NSDateFormatter alloc] init];
        df.dateFormat = @"yyyy-MM-dd HH:mm:ss.SSS";
        NSString *line = [NSString stringWithFormat:@"%@ [%s] %@\n",
                          [df stringFromDate:now], levelName(level), msg];
        [self _rotateIfNeeded];
        NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:self->_path];
        if (!fh) { return; }
        @try {
            [fh seekToEndOfFile];
            [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]];
        } @catch (NSException *e) {
            os_log_error(self->_oslog, "[TweakForce] log write failed: %{public}@", e);
        } @finally {
            [fh closeFile];
        }
    });
}

// Must be called on _q. / Должен вызываться на _q.
- (void)_rotateIfNeeded {
    NSDictionary *attrs = [NSFileManager.defaultManager attributesOfItemAtPath:_path error:nil];
    unsigned long long size = [attrs fileSize];
    if (size > TF_LOG_MAX_BYTES) {
        NSString *old = [_path stringByAppendingString:@".1"];
        [NSFileManager.defaultManager removeItemAtPath:old error:nil];
        [NSFileManager.defaultManager moveItemAtPath:_path toPath:old error:nil];
        [NSFileManager.defaultManager createFileAtPath:_path contents:nil attributes:nil];
    }
}

- (NSString *)tail:(NSUInteger)maxBytes {
    __block NSString *result = @"";
    dispatch_sync(_q, ^{
        if (!self->_path) return;
        NSData *data = [NSData dataWithContentsOfFile:self->_path];
        if (!data) return;
        NSUInteger len = data.length;
        NSUInteger start = (len > maxBytes) ? (len - maxBytes) : 0;
        NSData *slice = [data subdataWithRange:NSMakeRange(start, len - start)];
        result = [[NSString alloc] initWithData:slice encoding:NSUTF8StringEncoding] ?: @"";
    });
    return result;
}

@end
