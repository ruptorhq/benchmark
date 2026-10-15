/* board.h -- the minimal firmware base shared by the three CVE replay harnesses.
 *
 * Trimmed from the Ruptor private BSP. Only what the three app_*_hw.c harnesses touch
 * is kept: a byte-wide MMIO macro, the MemManage/MPU guard support, the hardware
 * fault-capture block at 0x20001000, and the Cortex-M4 vector table shape.
 */
#ifndef HARNESS_BOARD_H
#define HARNESS_BOARD_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "chip_stm32f446.h"                 /* RC_* register constants */

/* ---- MMIO (no capture SDK; just typed pointer access) ---- */
#define RREG(a)   (*(volatile uint32_t *)(a))
#define RR(a)     RREG(a)
#define RW(a, v)  (RREG(a) = (v))

/* ---- the hardware fault-capture block ---- */
#define RB_SHCSR       0xE000ED24u
#define RB_RESULT      0x20001000u      /* [magic, PC, MMFAR, CFSR] -- read back over SWD */
#define RB_RESULT_CLEAR() do {                                                                     \
        volatile uint32_t *_r = (volatile uint32_t *)RB_RESULT;                                    \
        _r[0] = _r[1] = _r[2] = _r[3] = 0;                                                         \
    } while (0)

/* ---- naked HardFault/BusFault handler recording {magic, PC, BFAR, CFSR} ---- */
#define RB_FAULT_HANDLER()                                                                         \
    __attribute__((naked)) void fault_handler(void) {                                              \
        __asm volatile(                                                                            \
            "mrs  r0, msp          \n ldr r1, [r0, #24]  \n ldr r3, =0x20001000 \n"                \
            "movw r2, #0x0000      \n movt r2, #0x600D   \n str r2, [r3, #0] \n str r1, [r3, #4]\n"\
            "movw r0, #0xED38      \n movt r0, #0xE000   \n ldr r0, [r0] \n str r0, [r3, #8]  \n" \
            "movw r0, #0xED28      \n movt r0, #0xE000   \n ldr r0, [r0] \n str r0, [r3, #12] \n b . \n"); }

#define RB_FAULT_ENABLE() do { RREG(RB_SHCSR) |= (1u << 17); } while (0)   /* BUSFAULTENA */

/* ---- Cortex-M4 vector table (56 entries covers the exceptions we route) ---- */
#define RB_VECTORS_FAULT()                                                                         \
    void default_handler(void) { for (;;) { } }                                                    \
    typedef void (*rb_vec_t)(void);                                                                \
    __attribute__((section(".isr_vector"), used)) const rb_vec_t vectors[56] = {                   \
        [0] = (rb_vec_t)RC_SP_TOP, [1] = reset_handler, [2] = default_handler,                     \
        [3] = fault_handler, [4] = default_handler, [5] = fault_handler, [6] = default_handler }

#define RB_VECTORS_PLAIN()                                                                         \
    void default_handler(void) { for (;;) { } }                                                    \
    typedef void (*rb_vec_t)(void);                                                                \
    __attribute__((section(".isr_vector"), used)) const rb_vec_t vectors[56] = {                   \
        [0] = (rb_vec_t)RC_SP_TOP, [1] = reset_handler, [2] = default_handler, [3] = default_handler }

/* ---- redzone guard: buffer followed by a 32-byte 32-aligned no-access region ----
 * The guard is mapped MPU no-access; a contiguous overflow becomes a precise
 * MemManage fault at the guard address. The replay script discovers each guard range
 * from the ELF symbol table (every symbol ending `_guard`).
 */
#define RB_RZ_SZ 32u
#define RB_GUARD(T, name, n) static struct { volatile T v[n]; volatile unsigned char rz[RB_RZ_SZ] __attribute__((aligned(32))); } name##_guard __attribute__((aligned(32)))
#define RB_BUF(name) (name##_guard.v)

#define RB_MPU_ARM_GUARD(name, region) do {                                                        \
        RREG(0xE000ED98u) = (region);                                 /* MPU_RNR */                \
        RREG(0xE000ED9Cu) = ((uint32_t)(name##_guard.rz)) | (1u << 4);/* MPU_RBAR = base | VALID */\
        RREG(0xE000EDA0u) = (1u << 0) | (4u << 1) | (0u << 24) | (1u << 28); /* RASR: EN, SIZE=32B, AP=no-access, XN */ \
    } while (0)
#define RB_MPU_ENABLE() do {                                                                       \
        RREG(RB_SHCSR) |= (1u << 16);                                 /* MEMFAULTENA */            \
        RREG(0xE000ED94u) = (1u << 0) | (1u << 2);                    /* MPU_CTRL: ENABLE|PRIVDEFENA */ \
        __asm volatile ("dsb"); __asm volatile ("isb");                                            \
    } while (0)

#endif /* HARNESS_BOARD_H */
