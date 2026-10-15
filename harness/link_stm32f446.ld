ENTRY(reset_handler)
MEMORY
{
  FLASH (rx) : ORIGIN = 0x8000000, LENGTH = 524288
  RAM  (rwx) : ORIGIN = 0x20000000, LENGTH = 131072
}
SECTIONS
{
  .isr_vector 0x8000000 : { KEEP(*(.isr_vector)) } > FLASH
  .text : { *(.text*) *(.rodata*) } > FLASH
  .data : { *(.data*) } > RAM AT> FLASH
  .bss : { *(.bss*) *(COMMON) } > RAM
}
