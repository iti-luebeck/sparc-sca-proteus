/*
 * AES-128 Masked Key Scenario B - Proteus Dynamic OoO Core
 *
 * TVLA Group B: Different key, same plaintext as scenario 1.
 * Used alongside scenario_aes128_masked_key (Group A) for TVLA comparison.
 *
 * Key B (NIST FIPS-197 Appendix A.1):
 *   key2      = 0x000102030405060708090a0b0c0d0e0f
 *   key_mask  = 0x0f1e2d3c4b5a69788796a5b4c3d2e1f0  (same as group A)
 *   key_share0 = key2 ^ key_mask = 0x0f1f2f3f4f5f6f7f8f9fafbfcfdfefff
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
 * TVLA Group B key share placed in .tainted_data — same section/address
 * layout as Group A so the taint injection address (0xB00) is unchanged.
 */

  .section ".tainted_data","aw",@progbits
  .align 4

/*
 * AES-128 Secret Key Share B (16 bytes) - TAINT SOURCE
 *
 * key2       = 0x000102030405060708090a0b0c0d0e0f  (NIST FIPS-197 App. A.1)
 * key_mask   = 0x0f1e2d3c4b5a69788796a5b4c3d2e1f0  (same mask as Group A)
 * key_share0 = key2 ^ key_mask = 0x0f1f2f3f4f5f6f7f8f9fafbfcfdfefff
 */
  .globl aes_key_share0
 aes_key_share0:
    .byte 0x0f, 0x1f, 0x2f, 0x3f
    .byte 0x4f, 0x5f, 0x6f, 0x7f
    .byte 0x8f, 0x9f, 0xaf, 0xbf
    .byte 0xcf, 0xdf, 0xef, 0xff


/*
 * ==========================================================================
 * DATA SECTION - Public Data (not tainted)
 * ==========================================================================
 */

  .section ".data","aw",@progbits
  .align 4

/*
 * Key mask (16 bytes) - NOT tainted (same as Group A)
 */
  .globl aes_key_mask
 aes_key_mask:
    .byte 0x0f, 0x1e, 0x2d, 0x3c
    .byte 0x4b, 0x5a, 0x69, 0x78
    .byte 0x87, 0x96, 0xa5, 0xb4
    .byte 0xc3, 0xd2, 0xe1, 0xf0

/*
 * State mask (16 bytes) - NOT tainted (same as Group A)
 */
  .globl aes_state_mask
 aes_state_mask:
    .byte 0xfb, 0x9b, 0xd8, 0xda
    .byte 0x7f, 0xcb, 0x79, 0x3c
    .byte 0xd5, 0x2c, 0x8a, 0x53
    .byte 0x6a, 0x99, 0x36, 0xd4

/*
 * Plaintext input block (16 bytes) - NOT tainted
 * FIPS-197 Appendix B test vector (same as Group A for direct comparison)
 */
  .globl aes_plaintext
 aes_plaintext:
    .byte 0x5d, 0x93, 0xf2, 0x8f
    .byte 0xc3, 0x42, 0x5d, 0x8f
    .byte 0x80, 0xd5, 0x01, 0xde
    .byte 0xa7, 0xae, 0x72, 0xe0

/*
 * Ciphertext output block (16 bytes)
 */
  .globl aes_ciphertext
 aes_ciphertext:
    .space 16, 0x00

/*
 * AES context / expanded key schedule (176 bytes)
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
