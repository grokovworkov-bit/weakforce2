/*
 * ============================================================================
 *  TweakForce — PACBypass.h (2_InjectionDaemon)
 * ============================================================================
 *  НАЗНАЧЕНИЕ:
 *  Публичный заголовок модуля PAC Bypass для архитектуры arm64e (A12/A13+).
 *
 *  ЧТО ТАКОЕ PAC (Pointer Authentication Codes):
 *  PAC — это аппаратная технология безопасности процессоров Apple архитектуры
 *  arm64e (начиная с A12 Bionic в iPhone XS и A13 Bionic в iPhone 11 Pro Max).
 *  PAC вычисляет криптографическую контрольную сумму (сигнатуру) для указателей
 *  функций и адресов возврата, записывая её в неиспользуемые старшие биты
 *  64-битного адреса. Перед переходом процессор выполняет валидацию сигнатуры
 *  (инструкции BRAA, BLRAA, BLRAAZ). Если подпись некорректна или отсутствует,
 *  вызывается аппаратное исключение (EXC_BAD_ACCESS / PAC failure trap).
 *
 *  ПОЧЕМУ arm64e ТРЕБУЕТ ОСОБОГО ПОДХОДА:
 *  1. thread_create_running / thread_set_state на arm64e требуют, чтобы
 *     значение PC (Program Counter) было предварительно подписано валидным
 *     PAC-ключом. Передача неподписанного виртуального адреса приводит к ошибке
 *     ядра KERN_INVALID_ARGUMENT или мгновенному крешу потока.
 *  2. Динамически сформированный в куче шеллкод не имеет кодовой подписи
 *     (Apple Code Signing) и не содержит PAC-сигнатур, что приводит к немедленному
 *     EXC_BAD_ACCESS при попытке выполнения.
 *  3. Вызов функций через указатель требует инструкций BLRAA/BLRAAZ
 *     (authenticated branch), а не классического неаутентифицированного BLR.
 *
 *  КАК РАБОТАЕТ ОБХОД (mach_vm_remap + MAP_JIT + dlopen Trampoline):
 *  1. Trampoline компилируется как обычная статическая C-функция нашего
 *     процесса с атрибутом __attribute__((noinline)). Компилятор Clang
 *     с флагами -fptrauth-* сам генерирует необходимые инструкции
 *     аутентифицированного вызова (BLRAA/BLRAAZ).
 *  2. Страница с кодом trampoline отображается в целевой процесс с помощью
 *     системного вызова mach_vm_remap. Ключевой инсайт: mach_vm_remap копирует
 *     уже подписанные кодовые страницы (Code Signing) нашего процесса в целевой.
 *     Подписи страниц сохраняются, и ядро не блокирует выполнение.
 *  3. Адрес PC для нового потока подписывается системным макросом
 *     arm_thread_state64_set_pc_fptr (использующим ptrauth_sign_unauthenticated
 *     с ключом ptrauth_key_process_independent_code).
 *  4. Адрес dlopen находится в dyld shared cache нашего процесса (общий для
 *     всех процессов iOS), очищается от PAC-бит через ptrauth_strip и передается
 *     в целевой процесс внутри структуры BootstrapArgs.
 * ============================================================================
 */

#pragma once

#ifndef PAC_BYPASS_H
#define PAC_BYPASS_H

#include <mach/mach.h>
#include <mach/arm/thread_status.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __OBJC__
#import <Foundation/Foundation.h>
#else
#ifndef BOOL
typedef bool BOOL;
#define YES true
#define NO false
#endif
#endif

// Условное подключение ptrauth.h для arm64e
#if __has_include(<ptrauth.h>)
#include <ptrauth.h>
#endif

// Условное подключение mach_vm.h или forward-декларации Mach VM API
#if __has_include(<mach/mach_vm.h>)
#include <mach/mach_vm.h>
#else
#ifndef mach_vm_address_t
typedef uint64_t mach_vm_address_t;
typedef uint64_t mach_vm_size_t;
typedef uint64_t mach_vm_offset_t;
#endif
#endif

// Константы RTLD для загрузки dylib
#ifndef RTLD_NOW
#define RTLD_NOW 0x2
#endif

#ifndef RTLD_GLOBAL
#define RTLD_GLOBAL 0x8
#endif

#ifndef RTLD_NOW_GLOBAL
#define RTLD_NOW_GLOBAL (RTLD_NOW | RTLD_GLOBAL) // 0xA
#endif

// Размер стека для bootstrap-потока в целевом процессе (64 КБ)
#define BOOTSTRAP_STACK_SIZE 65536

// Fallback макросы для ptrauth при компиляции без поддержки arm64e
#ifndef ptrauth_strip
#define ptrauth_strip(ptr, key) (ptr)
#endif

#ifndef ptrauth_key_function_pointer
#define ptrauth_key_function_pointer 0
#endif

#ifndef ptrauth_key_process_independent_code
#define ptrauth_key_process_independent_code 1
#endif

#ifndef arm_thread_state64_set_pc_fptr
#if defined(__darwin_arm_thread_state64_set_pc_fptr)
#define arm_thread_state64_set_pc_fptr(ts, fptr) __darwin_arm_thread_state64_set_pc_fptr(ts, fptr)
#elif defined(__has_feature) && __has_feature(ptrauth_calls)
#define arm_thread_state64_set_pc_fptr(ts, fptr) \
    ((ts).__opaque_pc = ptrauth_sign_unauthenticated((void*)(fptr), ptrauth_key_process_independent_code, 0))
#else
#define arm_thread_state64_set_pc_fptr(ts, fptr) ((ts).__pc = (uintptr_t)(fptr))
#endif
#endif

#ifndef arm_thread_state64_set_lr_fptr
#if defined(__darwin_arm_thread_state64_set_lr_fptr)
#define arm_thread_state64_set_lr_fptr(ts, fptr) __darwin_arm_thread_state64_set_lr_fptr(ts, fptr)
#elif defined(__has_feature) && __has_feature(ptrauth_calls)
#define arm_thread_state64_set_lr_fptr(ts, fptr) \
    ((ts).__opaque_lr = ptrauth_sign_unauthenticated((void*)(fptr), ptrauth_key_process_independent_code, 0))
#else
#define arm_thread_state64_set_lr_fptr(ts, fptr) ((ts).__lr = (uintptr_t)(fptr))
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Структура аргументов bootstrap загрузчика.
 * Размещается в памяти целевого процесса и передается в trampoline через регистр x0.
 */
typedef struct {
    mach_vm_address_t dlopen_fn; // Адрес dlopen в dyld shared cache
    char dylib_path[512];        // Путь к внедряемой библиотеке
    int rtld_flags;              // Флаги связывания (RTLD_NOW_GLOBAL = 0xA)
} BootstrapArgs;

/*
 * Детектирует архитектуру arm64e на текущем устройстве (через sysctl hw.cpusubtype).
 * Возвращает YES, если процессор является arm64e (A12 Bionic и новее).
 */
BOOL pac_is_arm64e(void);

/*
 * Находит виртуальный адрес dlopen в целевом процессе через dyld shared cache нашего процесса.
 * На arm64e снимает PAC-биты с указателя с помощью ptrauth_strip.
 * Возвращает "голый" адрес dlopen или 0 при ошибке.
 */
mach_vm_address_t pac_find_dlopen_in_task(task_t task);

/*
 * Отображает скомпилированную функцию tf_bootstrap_trampoline в адресное пространство целевого процесса.
 * Использует mach_vm_remap для копирования уже подписанных страниц бинарника.
 * Возвращает KERN_SUCCESS и записывает удаленный адрес trampoline в *out_addr.
 */
kern_return_t pac_map_jit_trampoline(task_t task,
                                      mach_vm_address_t *out_addr,
                                      mach_vm_size_t *out_size);

/*
 * Главная функция инъекции в задачу с поддержкой arm64e PAC.
 * Выполняет весь pipeline: поиск dlopen, remap trampoline, выделение стека и аргументов,
 * инициализацию thread_state с подписанным PC и запуск удаленного потока.
 */
kern_return_t pac_inject_into_task(task_t task, const char *dylib_path);

#if !__has_include(<mach/mach_vm.h>)
// Декларации Mach VM API при отсутствии mach_vm.h в стандартном SDK
kern_return_t mach_vm_remap(
    vm_map_t target_task,
    mach_vm_address_t *target_address,
    mach_vm_size_t size,
    mach_vm_offset_t mask,
    int flags,
    vm_map_t src_task,
    mach_vm_address_t src_address,
    boolean_t copy,
    vm_prot_t *cur_protection,
    vm_prot_t *max_protection,
    vm_inherit_t inheritance
);

kern_return_t mach_vm_allocate(
    vm_map_t target,
    mach_vm_address_t *address,
    mach_vm_size_t size,
    int flags
);

kern_return_t mach_vm_deallocate(
    vm_map_t target,
    mach_vm_address_t address,
    mach_vm_size_t size
);

kern_return_t mach_vm_write(
    vm_map_t target_task,
    mach_vm_address_t address,
    vm_offset_t data,
    mach_msg_type_number_t dataCnt
);
#endif

#ifdef __cplusplus
}
#endif

#endif /* PAC_BYPASS_H */
