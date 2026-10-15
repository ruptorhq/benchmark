/* STM32F446 register constants, generated from the ST SVD. */
#ifndef RUPTOR_CHIP_H
#define RUPTOR_CHIP_H

#define RC_CHIP            "stm32f446"
#define RC_SP_TOP          0x20020000u      /* SRAM top */
#define RC_USART2          0x40004400u
#define RC_GPIOA           0x40020000u
#define RC_RCC             0x40023800u
#define RC_PWR             0x40007000u
#define RC_FLASH_CTL       0x40023C00u

#define RC_U_SR_OFF        0x00u
#define RC_U_DR_OFF        0x04u
#define RC_U_RX_OFF        0x04u
#define RC_U_TX_OFF        0x04u
#define RC_U_BRR_OFF       0x08u
#define RC_U_CR1_OFF       0x0Cu

#define RC_GPIOA_MODER     (RC_GPIOA + 0x00u)
#define RC_GPIOA_OTYPER    (RC_GPIOA + 0x04u)
#define RC_GPIOA_OSPEEDR   (RC_GPIOA + 0x08u)
#define RC_GPIOA_PUPDR     (RC_GPIOA + 0x0Cu)
#define RC_GPIOA_AFRL      (RC_GPIOA + 0x20u)
#define RC_RCC_APB1ENR     (RC_RCC + 0x40u)
#define RC_RCC_AHB1ENR     (RC_RCC + 0x30u)

#endif
