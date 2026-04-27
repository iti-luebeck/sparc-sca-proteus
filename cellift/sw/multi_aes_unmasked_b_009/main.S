/*
 * AES-128 Unmasked Key 2 — Proteus Dynamic OoO Core
 *
 * TVLA Group B (unmasked): different key, same plaintext as Key 1.
 *
 * Key 2 (NIST FIPS-197 Appendix A.1):
 *   key = 0x000102030405060708090a0b0c0d0e0f
 */

  .section ".text.init","ax",@progbits
  .globl _start
  .align 2

_start:
    la sp, _stack_top

    la a0, aes_context
    la a1, aes_key        /* TAINT SOURCE */
    la a2, aes_plaintext
    la a3, aes_ciphertext

    call aes128_encrypt

    la t1, aes_ciphertext
    la t2, _scratch
    lw t3, 0(t1)
    sw t3, 0(t2)
    lw t3, 4(t1)
    sw t3, 4(t2)
    lw t3, 8(t1)
    sw t3, 8(t2)
    lw t3, 12(t1)
    sw t3, 12(t2)
    fence

    li t0, 0x30000000
    sw zero, 0(t0)

infinite_loop:
    j infinite_loop


/*
 * ==========================================================================
 * .tainted_data — secret key (TAINT SOURCE)
 * ==========================================================================
 * key = 0x000102030405060708090a0b0c0d0e0f
 */

  .section ".tainted_data","aw",@progbits
  .align 4

  .globl aes_key
aes_key:
    .byte 0x00, 0x01, 0x02, 0x03
    .byte 0x04, 0x05, 0x06, 0x07
    .byte 0x08, 0x09, 0x0a, 0x0b
    .byte 0x0c, 0x0d, 0x0e, 0x0f


/*
 * ==========================================================================
 * .data — public (not tainted)
 * ==========================================================================
 */

  .section ".data","aw",@progbits
  .align 4

  .globl aes_plaintext
aes_plaintext:
    .byte 0x95, 0x99, 0x18, 0xc6
    .byte 0x1d, 0x6d, 0x92, 0xee
    .byte 0x89, 0xb5, 0xd3, 0x68
    .byte 0x80, 0x82, 0x3d, 0x86

  .globl aes_ciphertext
aes_ciphertext:
    .space 16, 0x00

  .globl aes_context
aes_context:
    .space 176, 0x00

  .globl _scratch
_scratch:
    .space 16, 0x00
