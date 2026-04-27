  .section ".text.init","ax",@progbits
  .globl _start
  .align 2

_start:
    la sp, _stack_top

    /* Simple stack test: push/pop some values */
    li t0, 0xDEADBEEF
    addi sp, sp, -4
    sw t0, 0(sp)
    lw t1, 0(sp)
    addi sp, sp, 4

    /* Write to testDev to signal completion */
    li t0, 0x30000000
    sw zero, 0(t0)

loop:
    j loop
