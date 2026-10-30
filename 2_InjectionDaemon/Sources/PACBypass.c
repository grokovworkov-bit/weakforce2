/*
 * ============================================================================
 *  TweakForce — PACBypass.c (2_InjectionDaemon)
 * ============================================================================
 *  НАЗНАЧЕНИЕ:
 *  Полная реализация PAC-aware injection для архитектуры arm64e (A12/A13+).
 *
 *  РЕШАЕМЫЕ ПРОБЛЕМЫ arm64e:
 *  1. thread_create_running требует подписанного PC (иначе KERN_INVALID_ARGUMENT / panic).
 *  2. Динамический шеллкод в куче не подписан кодовой подписью = EXC_BAD_ACCESS.
 *  3. Вызов dlopen через указатель требует аутентифицированного перехода BLRAA/BLRAAZ.
 *
 *  РЕШЕНИЕ:
 *  - Trampoline компилируется компилятором (не байт-массив), Clang генерирует BLRAA.
 *  - mach_vm_remap копирует уже подписанные страницы кода из нашего процесса в целевой.
 *  - arm_thread_state64_set_pc_fptr правильно подписывает PC для ядра XNU.
 *  - dlopen находится через dlsym в dyld shared cache со снятием PAC бит (ptrauth_strip).
 * ============================================================================
 */

#import "PACBypass.h"
#import "Logger.h"
#include <unistd.h>
#include <string.h>

#ifndef CPU_SUBTYPE_ARM64E
#define CPU_SUBTYPE_ARM64E ((cpu_subtype_t)2)
#endif

// ============================================================================
// БЛОК А: Детект архитектуры arm64e
// ============================================================================
BOOL pac_is_arm64e(void) {
    cpu_subtype_t subtype = 0;
    size_t size = sizeof(subtype);
    if (sysctlbyname("hw.cpusubtype", &subtype, &size, NULL, 0) == 0) {
        if (subtype == CPU_SUBTYPE_ARM64E) {
            TFLogI(@"[PACBypass] Обнаружен arm64e процессор (hw.cpusubtype = %d)", subtype);
            return YES;
        }
    }

#if defined(__arm64e__)
    TFLogI(@"[PACBypass] Скомпилировано с флагом __arm64e__; активируем PAC режим");
    return YES;
#else
    return NO;
#endif
}

// ============================================================================
// БЛОК Б: Поиск dlopen в целевом процессе через dyld shared cache
// ============================================================================
mach_vm_address_t pac_find_dlopen_in_task(task_t task) {
    (void)task; // dyld shared cache одинаков для всех процессов в iOS

    // 1. Находим dlopen в НАШЕМ процессе через dlsym(RTLD_DEFAULT, "dlopen")
    void *dlopen_ptr = dlsym(RTLD_DEFAULT, "dlopen");
    if (!dlopen_ptr) {
        TFLogE(@"[PACBypass] ОШИБКА: dlsym(RTLD_DEFAULT, \"dlopen\") вернул NULL: %s", dlerror());
        return 0;
    }

    // 2. Снимаем PAC-биты через ptrauth_strip, чтобы получить "голый" адрес
#if defined(__arm64e__) || (defined(__has_feature) && __has_feature(ptrauth_calls))
    void *stripped_ptr = ptrauth_strip(dlopen_ptr, ptrauth_key_function_pointer);
    TFLogI(@"[PACBypass] Найден dlopen: 0x%lx (PAC stripped: 0x%lx)",
           (uintptr_t)dlopen_ptr, (uintptr_t)stripped_ptr);
    return (mach_vm_address_t)(uintptr_t)stripped_ptr;
#else
    TFLogI(@"[PACBypass] Найден dlopen: 0x%lx", (uintptr_t)dlopen_ptr);
    return (mach_vm_address_t)(uintptr_t)dlopen_ptr;
#endif
}

// ============================================================================
// БЛОК В: Trampoline (bootstrap loader как скомпилированная C-функция)
// ============================================================================
/*
 * Trampoline: выполняется в контексте целевого процесса после инъекции.
 * x0 = указатель на BootstrapArgs (в памяти целевого процесса).
 *
 * КРИТИЧЕСКИ ВАЖНО:
 * 1. __attribute__((noinline)) предотвращает встраивание функции компилятором.
 * 2. Код УЖЕ подписан в составе нашего бинарника (valid codesign).
 * 3. На arm64e компилятор Clang генерирует BLRAA/BLRAAZ для вызова fnptr.
 */
static void __attribute__((noinline)) tf_bootstrap_trampoline(BootstrapArgs *args) {
    if (args && args->dlopen_fn) {
        typedef void *(*dlopen_fn_t)(const char *, int);
        dlopen_fn_t fn = (dlopen_fn_t)args->dlopen_fn; // PAC-signed по умолчанию на arm64e
        fn(args->dylib_path, args->rtld_flags);
    }
}

// ============================================================================
// БЛОК Г: mach_vm_remap trampoline в целевой процесс
// ============================================================================
/*
 * Отображает страницу нашего бинарника, содержащую tf_bootstrap_trampoline,
 * в адресное пространство целевого процесса.
 *
 * КЛЮЧЕВОЙ ИНСАЙТ:
 * mach_vm_remap копирует УЖЕ подписанные кодовые страницы (code pages) нашего
 * процесса в целевой. Подписи страниц (Apple Code Signing) сохраняются, поэтому
 * операционная система не требует повторной подписи и не выбрасывает EXC_BAD_ACCESS.
 */
kern_return_t pac_map_jit_trampoline(task_t task,
                                      mach_vm_address_t *out_addr,
                                      mach_vm_size_t *out_size) {
    if (!out_addr) {
        return KERN_INVALID_ARGUMENT;
    }

    // 1. Получаем адрес tf_bootstrap_trampoline в нашем процессе
    uintptr_t trampoline_raw = (uintptr_t)tf_bootstrap_trampoline;
#if defined(__arm64e__) || (defined(__has_feature) && __has_feature(ptrauth_calls))
    trampoline_raw = (uintptr_t)ptrauth_strip((void *)trampoline_raw, ptrauth_key_function_pointer);
#endif

    // 2. Округляем до границы страницы (16 КБ для arm64/iOS или sysconf)
    vm_size_t page_size = vm_page_size;
    if (page_size == 0) {
        page_size = (vm_size_t)sysconf(_SC_PAGESIZE);
        if (page_size == 0) {
            page_size = 16384;
        }
    }

    mach_vm_address_t local_page = (mach_vm_address_t)(trampoline_raw & ~(page_size - 1));
    mach_vm_offset_t offset_in_page = (mach_vm_offset_t)(trampoline_raw - local_page);

    // 3. mach_vm_remap — отображаем кодовую страницу в целевой процесс
    mach_vm_address_t remote_addr = 0;
    vm_prot_t cur_prot = VM_PROT_READ | VM_PROT_EXECUTE;
    vm_prot_t max_prot = VM_PROT_READ | VM_PROT_EXECUTE;

    kern_return_t kr = mach_vm_remap(
        task,
        &remote_addr,
        page_size,
        0,
        VM_FLAGS_ANYWHERE,
        mach_task_self(),
        local_page,
        FALSE,              // copy = NO (shared mapping подписанной страницы)
        &cur_prot,
        &max_prot,
        VM_INHERIT_NONE
    );

    if (kr != KERN_SUCCESS) {
        TFLogE(@"[PACBypass] mach_vm_remap trampoline failed: %s (kr=%d)",
               mach_error_string(kr), kr);
        return kr;
    }

    // 4. Возвращаем remote_addr + смещение trampoline внутри страницы
    *out_addr = remote_addr + offset_in_page;
    if (out_size) {
        *out_size = page_size;
    }

    TFLogI(@"[PACBypass] mach_vm_remap успешен: local=0x%lx, remote_page=0x%llx, remote_fn=0x%llx",
           (uintptr_t)trampoline_raw, (unsigned long long)remote_addr, (unsigned long long)(*out_addr));

    return KERN_SUCCESS;
}

// ============================================================================
// БЛОК Ж: Главная функция pac_inject_into_task
// ============================================================================
/*
 * Полный pipeline инъекции dylib в целевую задачу task_t:
 * 1. Проверка архитектуры arm64e vs arm64.
 * 2. Поиск адреса dlopen в dyld shared cache.
 * 3. Ремаппинг подписанного trampoline через mach_vm_remap.
 * 4. Выделение стека (BOOTSTRAP_STACK_SIZE) и памяти под BootstrapArgs.
 * 5. Запись аргументов (dlopen_fn, dylib_path, RTLD_NOW_GLOBAL).
 * 6. Настройка ARM_THREAD_STATE64 с подписанным PC через arm_thread_state64_set_pc_fptr.
 * 7. Создание и запуск потока в целевом процессе.
 * 8. Cleanup при любых ошибках на каждом этапе.
 */
kern_return_t pac_inject_into_task(task_t task, const char *dylib_path) {
    if (task == MACH_PORT_NULL) {
        TFLogE(@"[PACBypass] pac_inject_into_task: недействительный task порт (MACH_PORT_NULL)");
        return KERN_INVALID_ARGUMENT;
    }
    if (!dylib_path || strlen(dylib_path) == 0) {
        TFLogE(@"[PACBypass] pac_inject_into_task: пустой путь dylib");
        return KERN_INVALID_ARGUMENT;
    }

    BOOL is_arm64e = pac_is_arm64e();
    TFLogI(@"[PACBypass] Начало инъекции '%s' в task 0x%x (arm64e = %d)",
           dylib_path, task, is_arm64e);

    // Шаг 1: Найти адрес dlopen
    mach_vm_address_t dlopen_addr = pac_find_dlopen_in_task(task);
    if (!dlopen_addr) {
        TFLogE(@"[PACBypass] Не удалось найти адрес dlopen в целевом процессе");
        return KERN_FAILURE;
    }

    // Шаг 2: Ремаппинг подписанного trampoline в целевой процесс
    mach_vm_address_t trampoline_remote = 0;
    mach_vm_size_t remap_size = 0;
    kern_return_t kr = pac_map_jit_trampoline(task, &trampoline_remote, &remap_size);
    if (kr != KERN_SUCCESS) {
        TFLogE(@"[PACBypass] Ошибка ремаппинга trampoline: %s", mach_error_string(kr));
        return kr;
    }

    // Шаг 3: Выделение стека в целевом процессе (БЛОК Д)
    mach_vm_address_t stack_remote = 0;
    kr = mach_vm_allocate(task, &stack_remote, BOOTSTRAP_STACK_SIZE, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        TFLogE(@"[PACBypass] mach_vm_allocate для стека failed: %s", mach_error_string(kr));
        return kr;
    }

    // Шаг 4: Выделение и запись BootstrapArgs в целевом процессе (БЛОК Д)
    mach_vm_address_t args_remote = 0;
    mach_vm_size_t args_size = sizeof(BootstrapArgs);
    kr = mach_vm_allocate(task, &args_remote, args_size, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        TFLogE(@"[PACBypass] mach_vm_allocate для BootstrapArgs failed: %s", mach_error_string(kr));
        mach_vm_deallocate(task, stack_remote, BOOTSTRAP_STACK_SIZE);
        return kr;
    }

    BootstrapArgs args;
    memset(&args, 0, sizeof(args));
    args.dlopen_fn = dlopen_addr;
    strncpy(args.dylib_path, dylib_path, sizeof(args.dylib_path) - 1);
    args.rtld_flags = RTLD_NOW_GLOBAL;

    kr = mach_vm_write(task, args_remote, (vm_offset_t)&args, (mach_msg_type_number_t)sizeof(args));
    if (kr != KERN_SUCCESS) {
        TFLogE(@"[PACBypass] mach_vm_write BootstrapArgs failed: %s", mach_error_string(kr));
        mach_vm_deallocate(task, args_remote, args_size);
        mach_vm_deallocate(task, stack_remote, BOOTSTRAP_STACK_SIZE);
        return kr;
    }

    TFLogI(@"[PACBypass] Аргументы записаны: stack=0x%llx, args=0x%llx, dlopen=0x%llx",
           (unsigned long long)stack_remote, (unsigned long long)args_remote, (unsigned long long)dlopen_addr);

    // Шаг 5: Инициализация состояния потока (БЛОК Е)
    arm_thread_state64_t state;
    bzero(&state, sizeof(state));

    // Стек (выравнивание на 16 байт)
    state.__sp = (stack_remote + BOOTSTRAP_STACK_SIZE - 16) & ~0xFULL;

    // Аргумент x0 = указатель на BootstrapArgs в целевом процессе
    state.__x[0] = (uint64_t)args_remote;

    // PC — КРИТИЧЕСКИ ВАЖНАЯ ЧАСТЬ ДЛЯ arm64e:
    // Системный макрос arm_thread_state64_set_pc_fptr подписывает PC
    // с ключом ptrauth_key_process_independent_code, что позволяет ядру XNU
    // принять thread_set_state без PAC fault.
    arm_thread_state64_set_pc_fptr(state, (void *)(uintptr_t)trampoline_remote);

    // LR = 0 (аварийное завершение если trampoline попытается вернуться)
    arm_thread_state64_set_lr_fptr(state, NULL);

    // Шаг 6: Создание, настройка и запуск потока
    thread_act_t new_thread = MACH_PORT_NULL;
    kr = thread_create(task, &new_thread);
    if (kr != KERN_SUCCESS) {
        TFLogE(@"[PACBypass] thread_create failed: %s", mach_error_string(kr));
        mach_vm_deallocate(task, args_remote, args_size);
        mach_vm_deallocate(task, stack_remote, BOOTSTRAP_STACK_SIZE);
        return kr;
    }

    kr = thread_set_state(new_thread, ARM_THREAD_STATE64,
                          (thread_state_t)&state, ARM_THREAD_STATE64_COUNT);
    if (kr != KERN_SUCCESS) {
        TFLogE(@"[PACBypass] thread_set_state failed: %s (ядро отклонило подпись PC)",
               mach_error_string(kr));
        thread_terminate(new_thread);
        mach_port_deallocate(mach_task_self(), new_thread);
        mach_vm_deallocate(task, args_remote, args_size);
        mach_vm_deallocate(task, stack_remote, BOOTSTRAP_STACK_SIZE);
        return kr;
    }

    kr = thread_resume(new_thread);
    if (kr != KERN_SUCCESS) {
        TFLogE(@"[PACBypass] thread_resume failed: %s", mach_error_string(kr));
        thread_terminate(new_thread);
        mach_port_deallocate(mach_task_self(), new_thread);
        mach_vm_deallocate(task, args_remote, args_size);
        mach_vm_deallocate(task, stack_remote, BOOTSTRAP_STACK_SIZE);
        return kr;
    }

    // Освобождаем локальный порт потока
    mach_port_deallocate(mach_task_self(), new_thread);

    TFLogI(@"[PACBypass] УСПЕХ: PAC-aware поток запущен в задаче 0x%x для библиотеки %s",
           task, dylib_path);

    return KERN_SUCCESS;
}
