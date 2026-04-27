/*
 * AES-128 Masked Key Scenario - Proteus Dynamic OoO Core
 *
 * Main entry point and data definitions for the masked AES-128 test.
 * The masked key share is placed in a tainted section for CellIFT tracking.
 *
 * Proteus boots at 0x80000000, uses RV32IM (no compressed).
 */

  .section ".text.init","ax",@progbits
  .globl _start
  .align 2

_start:
    /* Set up stack pointer */
    la sp, _stack_top

    /*
     * Call masked AES-128 encryption
     *
     * Arguments:
     *   a0 = pointer to AES context (expanded keys)
     *   a1 = pointer to key_share0 (TAINTED)
     *   a2 = pointer to key_mask (NOT tainted)
     *   a3 = pointer to 16-byte plaintext
     *   a4 = pointer to 16-byte state mask
     *   a5 = pointer to 16-byte ciphertext output
     */
    la a0, aes_context
    la a1, aes_key_share0     /* TAINT SOURCE (masked key share) */
    la a2, aes_key_mask
    la a3, aes_plaintext
    la a4, aes_state_mask
    la a5, aes_ciphertext

    /* Call the masked AES encryption function */
    call aes128_masked_encrypt

    /* Force ciphertext out of L1 cache by reading all 16 bytes
     * and writing them to a scratch location (forces writeback) */
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

    /* Signal completion via testDev (write 0 = pass) */
    li t0, 0x30000000         /* testDev address */
    sw zero, 0(t0)

    /* Done - infinite loop */
infinite_loop:
    j infinite_loop


/*
 * ==========================================================================
 * DATA SECTION - Tainted Key Share
 * ==========================================================================
 * The AES key share is placed in a special .tainted_data section.
 * In CellIFT simulation, mark this memory region as tainted.
 */

  .section ".tainted_data","aw",@progbits
  .align 4

/*
 * AES-128 Secret Key Share (16 bytes) - TAINT SOURCE
 *
 * key_share0 = key ^ key_mask
 * Actual key = 0x2b7e151628aed2a6abf7158809cf4f3c (FIPS-197 test key)
 * key_mask   = 0x0f1e2d3c4b5a69788796a5b4c3d2e1f0
 * key_share0 = key ^ key_mask = 0x24603826a63f4bbde2c61b03cca1daec
 */
  .globl aes_key_share0
 aes_key_share0:
    .byte 0x24, 0x60, 0x38, 0x2a
    .byte 0x63, 0xf4, 0xbb, 0xde
    .byte 0x2c, 0x61, 0xb0, 0x3c
    .byte 0xca, 0x1d, 0xae, 0xcc


/*
 * ==========================================================================
 * DATA SECTION - Public Data (not tainted)
 * ==========================================================================
 */

  .section ".data","aw",@progbits
  .align 4

/*
 * Key mask (16 bytes) - NOT tainted
 */
  .globl aes_key_mask
 aes_key_mask:
    .byte 0x0f, 0x1e, 0x2d, 0x3c
    .byte 0x4b, 0x5a, 0x69, 0x78
    .byte 0x87, 0x96, 0xa5, 0xb4
    .byte 0xc3, 0xd2, 0xe1, 0xf0

/*
 * State mask (16 bytes) - NOT tainted
 * Used to keep the AES state masked during rounds.
 */
  .globl aes_state_mask
 aes_state_mask:
    .byte 0x62, 0x15, 0x58, 0xc7
    .byte 0x73, 0xf6, 0x6f, 0x8f
    .byte 0x41, 0x92, 0x64, 0x65
    .byte 0x25, 0xac, 0x0d, 0x32

/*
 * Plaintext input block (16 bytes) - NOT tainted
 * FIPS-197 Appendix B test vector
 */
  .globl aes_plaintext
 aes_plaintext:
    .byte 0x02, 0x99, 0x41, 0xd5
    .byte 0xcf, 0x45, 0x4c, 0xbd
    .byte 0x8c, 0x26, 0xbb, 0x9e
    .byte 0xc2, 0x1b, 0x8f, 0x1e

/*
 * Ciphertext output block (16 bytes)
 * Will become tainted after encryption.
 */
  .globl aes_ciphertext
 aes_ciphertext:
    .space 16, 0x00

/*
 * AES context / expanded key schedule (176 bytes)
 * Will become tainted during key expansion.
 */
  .globl aes_context
 aes_context:
    .space 176, 0x00

/*
 * Scratch area for cache flush
 */
  .globl _scratch
 _scratch:
    .space 16, 0x00
