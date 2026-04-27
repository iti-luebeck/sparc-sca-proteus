OUTPUT_ARCH( "riscv" )
ENTRY(_start)

SECTIONS
{
  /* Proteus boots from 0x80000000 */
  . = 0x80000000;
  .text.init : { *(.text.init) }
  . = ALIGN(0x100);
  .text : { *(.text) }
  . = ALIGN(0x100);
  .rodata : { *(.rodata*) }
  . = ALIGN(0x100);
  .data : { *(.data*) }
  . = ALIGN(0x100);
  .bss : { *(.bss*) }
  . = ALIGN(0x100);

  /* Tainted data section - masked key share lives here */
  . = ALIGN(0x100);
  .tainted_data : { *(.tainted_data) }
  tainted_region_start = ADDR(.tainted_data);
  tainted_region_end = ADDR(.tainted_data) + SIZEOF(.tainted_data);

  /* Stack placed after all data (grows downward from _stack_top) */
  . = ALIGN(0x100);
  . += 0x1000;
  _stack_top = .;
}
