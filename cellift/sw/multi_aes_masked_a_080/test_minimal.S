  .section ".text.init","ax",@progbits
  .globl _start
  .align 2

_start:
    /* Minimal test: just write to testDev immediately */
    li t0, 0x30000000
    sw zero, 0(t0)

loop:
    j loop
