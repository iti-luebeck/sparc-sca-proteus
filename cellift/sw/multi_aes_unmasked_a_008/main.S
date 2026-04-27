/*
 * AES-128 Unmasked Key 1 — Proteus Dynamic OoO Core
 *
 * TVLA Group A (unmasked): direct secret key in .tainted_data.
 * Used alongside scenario_aes128_unmasked_key2 (Group B) for TVLA.
 *
 * Key 1 (FIPS-197 Appendix B test key):
 *   key = 0x2b7e151628aed2a6abf7158809cf4f3c
 *
 * Taint: entire 16-byte key is fully tainted (no masking).
 */

  .section ".text.init","ax",@progbits
  .globl _start
  .align 2

_start:
    la sp, _stack_top

    /*
     * aes128_encrypt(ctx, key, plaintext, ciphertext)
     *   a0 = ctx       (176-byte key schedule buffer)
     *   a1 = key       (TAINTED — the secret)
     *   a2 = plaintext
     *   a3 = ciphertext
     */
    la a0, aes_context
    la a1, aes_key        /* TAINT SOURCE */
    la a2, aes_plaintext
    la a3, aes_ciphertext

    call aes128_encrypt

    /* Cache flush: force ciphertext writeback */
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
 * Placed in its own section so the linker script can align it
 * independently, keeping the taint injection address stable across
 * masked and unmasked variants.
 *
 * key = 0x2b7e151628aed2a6abf7158809cf4f3c
 */

  .section ".tainted_data","aw",@progbits
  .align 4

  .globl aes_key
aes_key:
    .byte 0x2b, 0x7e, 0x15, 0x16
    .byte 0x28, 0xae, 0xd2, 0xa6
    .byte 0xab, 0xf7, 0x15, 0x88
    .byte 0x09, 0xcf, 0x4f, 0x3c


/*
 * ==========================================================================
 * .data — public (not tainted)
 * ==========================================================================
 */

  .section ".data","aw",@progbits
  .align 4

  .globl aes_plaintext
aes_plaintext:
    .byte 0xcd, 0x8d, 0x40, 0x43
    .byte 0x99, 0x02, 0x17, 0xe8
    .byte 0x96, 0xb7, 0x1b, 0x19
    .byte 0x2d, 0x8b, 0xd1, 0x77

  .globl aes_ciphertext
aes_ciphertext:
    .space 16, 0x00

  .globl aes_context
aes_context:
    .space 176, 0x00

  .globl _scratch
_scratch:
    .space 16, 0x00
