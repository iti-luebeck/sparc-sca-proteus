/*
 * randombytes_stub.c
 *
 * crypto_kem_dec does not call randombytes, but crypto_kem_keypair (in the
 * same translation unit) does. This stub satisfies the linker without
 * pulling in OpenSSL or any OS entropy source.
 */
int randombytes(unsigned char *x, unsigned long long xlen)
{
    (void)x;
    (void)xlen;
    return 0;
}
