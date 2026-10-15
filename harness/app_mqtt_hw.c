/*
 * ruptor hardware T2 validation for the MQTT-C redzone-read finding (CVE-2026-54412). The fuzzer found this
 * out-of-bounds READ on the fuzzer (the Ruptor fuzzer (private tooling)); this harness REPLAYS the minimized
 * repro on the REAL STM32F446 with the receive buffer's guard mapped MPU no-access, so the same over-read faults on
 * silicon -> the sanitizer-class finding becomes T2 (hardware-proven).
 *
 * Mechanism: a load into an MPU no-access region raises a precise MemManage (CFSR.DACCVIOL, MMFAR = the faulting
 * address) -- exactly as a store does. That store case is already hardware-confirmed for isotp-c's redzone-WRITE
 * (scripts/hw/run_hw_redzone.py, board/nucleo_f446re_mpu.json); this harness covers the READ case with the same guard.
 *
 * src/mqtt.c + include/mqtt.h are pristine; only mqtt_pal.h is the (freestanding) platform port. The repro PUBLISH is
 * baked in (real-USART delivery is tracked separately; what T2 asserts is that the fuzzer-found input faults the chip).
 */
#include "board.h"
#include <stddef.h>
#include <limits.h>
#include <stdarg.h>

#define RB_RESULT_ADDR 0x20001000u

void *memcpy(void *d, const void *s, size_t n) { unsigned char *a = d; const unsigned char *b = s; while (n--) *a++ = *b++; return d; }
void *memset(void *d, int v, size_t n) { unsigned char *a = d; while (n--) *a++ = (unsigned char)v; return d; }
void *memmove(void *d, const void *s, size_t n) { unsigned char *a = d; const unsigned char *b = s;
    if (a < b) { while (n--) *a++ = *b++; } else { a += n; b += n; while (n--) *--a = *--b; } return d; }
size_t strlen(const char *s) { const char *p = s; while (*p) p++; return (size_t)(p - s); }
typedef long ssize_t;
ssize_t mqtt_pal_sendall(int fd, const void *buf, size_t len, int flags) { (void)fd; (void)buf; (void)len; (void)flags; return 0; }
ssize_t mqtt_pal_recvall(int fd, void *buf, size_t bufsz, int flags) { (void)fd; (void)buf; (void)bufsz; (void)flags; return 0; }

#include <mqtt.h>
#include "mqtt-c/src/mqtt.c"

#define RXCAP 64u
RB_GUARD(uint8_t, rxbuf, RXCAP);
volatile int sink;

/* the fuzzer's repro for CVE-2026-54412: a PUBLISH, remaining_length=4, topic_name_size=5 -> application_message_size
 * underflows; the subscriber read then walks off rxbuf into the guard. */
static const uint8_t repro[] = { 0x30, 0x04, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00 };

__attribute__((naked)) void rb_mem_fault(void)
{
    __asm volatile(
        "mrs  r0, msp          \n ldr r1, [r0, #24] \n"
        "movw r3, #0x1000      \n movt r3, #0x2000  \n"                               /* r3 = 0x20001000 (no literal pool) */
        "movw r2, #0x0000      \n movt r2, #0x600D  \n str r2, [r3, #0]  \n"
        "str  r1, [r3, #4]     \n"
        "movw r0, #0xED34      \n movt r0, #0xE000  \n ldr r0, [r0] \n str r0, [r3, #8]  \n"   /* MMFAR */
        "movw r0, #0xED28      \n movt r0, #0xE000  \n ldr r0, [r0] \n str r0, [r3, #12] \n"   /* CFSR  */
        "b . \n");
}

void reset_handler(void)
{
    volatile uint32_t *res = (volatile uint32_t *)RB_RESULT_ADDR;
    res[0] = res[1] = res[2] = res[3] = 0;
    /* RLOG stub removed */
    for (unsigned i = 0; i < sizeof(repro); i++) { RB_BUF(rxbuf)[i] = repro[i]; }
    RB_MPU_ARM_GUARD(rxbuf, 0);                          /* guard -> MPU no-access */
    RB_MPU_ENABLE();                                     /* MemManage + MPU on: the OOB read now faults on silicon */

    const uint8_t *pkt = (const uint8_t *)RB_BUF(rxbuf);
    struct mqtt_response resp;
    ssize_t rv = mqtt_unpack_fixed_header(&resp, pkt, sizeof(repro));
    if (rv > 0 && resp.fixed_header.control_type == MQTT_CONTROL_PUBLISH) {
        mqtt_unpack_publish_response(&resp, pkt + rv);
        const uint8_t *msg = (const uint8_t *)resp.decoded.publish.application_message;
        for (size_t i = 0; i < resp.decoded.publish.application_message_size; i++) {
            sink ^= msg[i];                              /* OOB read into the no-access guard -> MemManage */
        }
    }
    /* RLOG stub removed */
    for (;;) { }
}

typedef void (*rb_vec_t)(void);
__attribute__((section(".isr_vector"), used)) const rb_vec_t vectors[56] = {
    [0] = (rb_vec_t)RC_SP_TOP, [1] = reset_handler, [2] = rb_mem_fault,
    [3] = rb_mem_fault, [4] = rb_mem_fault, [5] = rb_mem_fault, [6] = rb_mem_fault,
};
