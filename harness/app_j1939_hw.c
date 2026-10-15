/*
 * ruptor hardware T2 validation for the Open-SAE-J1939 finding (CVE-2026-37534). The fuzzer found this integer
 * underflow -> out-of-bounds subscript on the Ruptor fuzzer (built with --ubsan so the compiler's object-bounds
 * check traps). This harness replays the minimized repro (a TP.DT frame with sequence number 0) on the REAL F446,
 * also built with --ubsan: the bounds check executes a `udf` (undefined instruction) at the OOB subscript, which is a
 * real UsageFault on silicon -- so the finding is hardware-reproducible (T2), not model-only.
 *
 * Built with RUPTOR_UBSAN (the runner passes --ubsan for target "j1939_hw"). UsageFault is enabled so the udf is
 * caught precisely; the handler records {magic, PC, CFSR} to 0x20001000, read over SWD. j1939/* is pristine; the
 * non-TPDT layer functions are link-only no-op shims (the seq=0 frame never reaches the complete-message path).
 */
#include "board.h"
#include "open-sae-j1939/Src/Open_SAE_J1939/Open_SAE_J1939.h"

#define RB_RESULT_ADDR 0x20001000u
#define SCB_SHCSR 0xE000ED24u
#define SCB_CFSR  0xE000ED28u

void *memcpy(void *d, const void *s, size_t n) { unsigned char *a = d; const unsigned char *b = s; while (n--) *a++ = *b++; return d; }
void *memset(void *d, int v, size_t n) { unsigned char *a = d; while (n--) *a++ = (unsigned char)v; return d; }

void SAE_J1939_Read_Response_Request_DM1(J1939 *j, uint8_t SA, uint8_t d[], uint8_t n) { (void)j; (void)SA; (void)d; (void)n; }
void SAE_J1939_Read_Response_Request_DM2(J1939 *j, uint8_t SA, uint8_t d[], uint8_t n) { (void)j; (void)SA; (void)d; (void)n; }
void SAE_J1939_Read_Response_Request_Component_Identification(J1939 *j, uint8_t SA, uint8_t d[]) { (void)j; (void)SA; (void)d; }
void SAE_J1939_Read_Response_Request_ECU_Identification(J1939 *j, uint8_t SA, uint8_t d[]) { (void)j; (void)SA; (void)d; }
void SAE_J1939_Read_Response_Request_Software_Identification(J1939 *j, uint8_t SA, uint8_t d[]) { (void)j; (void)SA; (void)d; }
void SAE_J1939_Read_Response_Request_Proprietary_A(J1939 *j, uint8_t SA, uint8_t d[]) { (void)j; (void)SA; (void)d; }
void SAE_J1939_Read_Response_Request_Proprietary_B(J1939 *j, uint8_t SA, uint32_t PGN, uint8_t d[]) { (void)j; (void)SA; (void)PGN; (void)d; }
void SAE_J1939_Read_Commanded_Address(J1939 *j, uint8_t d[]) { (void)j; (void)d; }
void SAE_J1939_Read_Binary_Data_Transfer_DM16(J1939 *j, uint8_t SA, uint8_t d[]) { (void)j; (void)SA; (void)d; }
ENUM_J1939_STATUS_CODES SAE_J1939_Send_Transport_Protocol_Connection_Management(J1939 *j, uint8_t DA) { (void)j; (void)DA; return STATUS_SEND_OK; }
ENUM_J1939_STATUS_CODES CAN_Send_Message(uint32_t ID, uint8_t data[]) { (void)ID; (void)data; return STATUS_SEND_OK; }
void CAN_Delay(uint8_t ms) { (void)ms; }

#include "open-sae-j1939/Src/SAE_J1939/SAE_J1939-21_Transport_Layer/Transport_Protocol_Data_Transfer.c"

__attribute__((naked)) void rb_usage_fault(void)
{
    __asm volatile(
        "mrs  r0, msp          \n ldr r1, [r0, #24] \n"
        "ldr  r3, =0x20001000  \n"
        "movw r2, #0x0000      \n movt r2, #0x600D  \n str r2, [r3, #0]  \n"   /* magic */
        "str  r1, [r3, #4]     \n"                                             /* PC (the udf) */
        "movw r0, #0xED28      \n movt r0, #0xE000  \n ldr r0, [r0] \n str r0, [r3, #8]  \n"   /* CFSR */
        "movw r2, #0x0000      \n str r2, [r3, #12] \n"
        "b . \n");
}

static J1939 j1939;
static const uint8_t repro[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };   /* TP.DT, sequence number 0 -> index = 0-1 = 255 */
volatile int sink;

void reset_handler(void)
{
    volatile uint32_t *res = (volatile uint32_t *)RB_RESULT_ADDR;
    res[0] = res[1] = res[2] = res[3] = 0;
    /* RLOG stub removed */
    RREG(SCB_SHCSR) |= (1u << 18);                        /* USAGEFAULTENA: catch the udf precisely */
    uint8_t frame[8];
    for (uint8_t i = 0; i < 8u; i++) frame[i] = repro[i];
    SAE_J1939_Read_Transport_Protocol_Data_Transfer(&j1939, 0x01u, frame);   /* --ubsan bounds trap -> udf */
    sink += j1939.from_other_ecu_tp_dt.sequence_number;
    /* RLOG stub removed */
    for (;;) { }
}

typedef void (*rb_vec_t)(void);
__attribute__((section(".isr_vector"), used)) const rb_vec_t vectors[56] = {
    [0] = (rb_vec_t)RC_SP_TOP, [1] = reset_handler, [2] = rb_usage_fault,
    [3] = rb_usage_fault, [4] = rb_usage_fault, [5] = rb_usage_fault, [6] = rb_usage_fault,
};
