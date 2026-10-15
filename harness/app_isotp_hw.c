/*
 * ruptor hardware T2 validation for the isotp-c redzone finding (CVE-2026-37535). The fuzzer found this out-of-bounds
 * write on the fuzzer (the Ruptor fuzzer (private tooling)); this harness REPLAYS the minimized repro on
 * the REAL STM32F446 with the receive buffer's guard mapped MPU no-access, proving the same OOB faults on silicon ->
 * the sanitizer-class finding becomes T2 (hardware-proven).
 *
 * The repro frame is baked in (the real-USART/VCP delivery path is tracked separately; what T2 asserts is that the
 * fuzzer-found input faults the real chip). The isotp reassembler is pristine openxc/isotp-c; allocate() hands it a
 * right-aligned slot in the guarded buffer, so the First Frame's FF_DL<6 drives the unconditional 6-byte copy past the
 * buffer into the guard. On the Ruptor fuzzer the fuzzer's own sanitizer flags it; here the MPU turns it into a precise
 * MemManage fault. The handler records {magic, PC, MMFAR, CFSR} to 0x20001000, read back over SWD.
 */
#include "board.h"
#include <isotp/isotp.h>

#define RB_RESULT_ADDR 0x20001000u

void *memcpy(void *d, const void *s, size_t n) { unsigned char *a = d; const unsigned char *b = s; while (n--) *a++ = *b++; return d; }
void *memset(void *d, int v, size_t n) { unsigned char *a = d; while (n--) *a++ = (unsigned char)v; return d; }
int snprintf(char *s, size_t n, const char *f, ...) { (void)f; if (s && n) s[0] = 0; return 0; }

#define ACAP 128u
RB_GUARD(uint8_t, abuf, ACAP);
uint8_t *allocate(size_t size) { if (size > ACAP) size = ACAP; return (uint8_t *)&RB_BUF(abuf)[ACAP - size]; }
void free_allocated(uint8_t *data) { (void)data; }
static void rlog(const char *fmt, ...) { (void)fmt; }
static bool rsend(const uint32_t arb, const uint8_t *data, const uint8_t size) { (void)arb; (void)data; (void)size; return true; }

#include <isotp/isotp.c>
#include <isotp/receive.c>
#include <isotp/send.c>
#include <bitfield/bitfield.c>
#include <bitfield/bitarray.c>

__attribute__((naked)) void rb_mem_fault(void)
{
    __asm volatile(
        "mrs  r0, msp          \n ldr r1, [r0, #24] \n"
        "ldr  r3, =0x20001000  \n"
        "movw r2, #0x0000      \n movt r2, #0x600D  \n str r2, [r3, #0]  \n"
        "str  r1, [r3, #4]     \n"
        "movw r0, #0xED34      \n movt r0, #0xE000  \n ldr r0, [r0] \n str r0, [r3, #8]  \n"
        "movw r0, #0xED28      \n movt r0, #0xE000  \n ldr r0, [r0] \n str r0, [r3, #12] \n"
        "b . \n");
}

#define ARB 0x7E8u
/* the fuzzer's repro frame for CVE-2026-37535: a First Frame declaring FF_DL=2 (< 6) */
static const uint8_t repro[] = { 0x10, 0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
volatile int sink;

void reset_handler(void)
{
    volatile uint32_t *res = (volatile uint32_t *)RB_RESULT_ADDR;
    res[0] = res[1] = res[2] = res[3] = 0;
    /* RLOG stub removed */
    RB_MPU_ARM_GUARD(abuf, 0);                           /* guard -> MPU no-access */
    RB_MPU_ENABLE();                                     /* MemManage + MPU on: the OOB now faults on silicon */

    IsoTpShims shims = isotp_init_shims(rlog, rsend, 0);
    IsoTpReceiveHandle handle = isotp_receive(&shims, ARB, 0);
    uint8_t frame[8];
    for (uint8_t i = 0; i < 8u; i++) frame[i] = repro[i];
    IsoTpMessage m = isotp_continue_receive(&shims, &handle, ARB, frame, 8u);   /* OOB write -> MemManage */
    sink += m.size;

    /* RLOG stub removed */
    for (;;) { }
}

typedef void (*rb_vec_t)(void);
__attribute__((section(".isr_vector"), used)) const rb_vec_t vectors[56] = {
    [0] = (rb_vec_t)RC_SP_TOP, [1] = reset_handler, [2] = rb_mem_fault,
    [3] = rb_mem_fault, [4] = rb_mem_fault, [5] = rb_mem_fault, [6] = rb_mem_fault,
};
