//
// Created by cp723 on 2/7/2019.
//

#include "util.h"

#include <openssl/err.h>
#include <openssl/evp.h>

void decode_ordinal(mpz_t perm, mpz_t ordinal, size_t mismatches, size_t key_size) {
    mpz_t binom;
    mpz_init(binom);

    mpz_set_ui(perm, 0);
    for (unsigned long bit = key_size * 8 - 1; mismatches > 0; bit--)
    {
        mpz_bin_uiui(binom, bit, mismatches);
        if (mpz_cmp(ordinal, binom) >= 0)
        {
            mpz_sub(ordinal, ordinal, binom);
            mpz_setbit(perm, bit);
            mismatches--;
        }
    }

    mpz_clear(binom);
}

void get_random_permutation(mpz_t perm, size_t mismatches, size_t key_size, gmp_randstate_t randstate) {
    mpz_t ordinal, binom;
    mpz_inits(ordinal, binom, NULL);

    mpz_bin_uiui(binom, key_size * 8, mismatches);

    mpz_urandomm(ordinal, randstate, binom);
    decode_ordinal(perm, ordinal, mismatches, key_size);

    mpz_clears(ordinal, binom, NULL);
}

void generate_starting_permutations(mpz_t *starting_perms, size_t starting_perms_size, size_t mismatches,
                                    size_t key_size) {
    // Always set the first one to the global first permutation
    gmp_assign_first_permutation(starting_perms[0], mismatches);

    mpz_t ordinal, chunk_size;
    mpz_inits(ordinal, chunk_size, NULL);

    mpz_bin_uiui(chunk_size, key_size * 8, mismatches);
    mpz_tdiv_q_ui(chunk_size, chunk_size, starting_perms_size);

    for(size_t i = 0; i < starting_perms_size; i++) {
        mpz_mul_ui(ordinal, chunk_size, i);

        decode_ordinal(starting_perms[i], ordinal, mismatches, key_size);
    }

    mpz_clears(ordinal, chunk_size, NULL);
}

int encrypt(const unsigned char* key, const unsigned char* msg, size_t msgLen, unsigned char* cipher, int* outlen) {
    int tmplen;

    EVP_CIPHER_CTX *ctx;

    if((ctx = EVP_CIPHER_CTX_new()) == NULL) {
        return 0;
    }

    if(!EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL)) {
        fprintf(stderr, "ERROR: EVP_EncryptInit_ex failed.\nOpenSSL Error: %s\n",
                ERR_error_string(ERR_get_error(), NULL));
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    if(!EVP_EncryptUpdate(ctx, cipher, outlen, msg, (int)msgLen)) {
        fprintf(stderr, "ERROR: EVP_EncryptUpdate failed.\nOpenSSL Error: %s\n",
                ERR_error_string(ERR_get_error(), NULL));
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    if(!EVP_EncryptFinal_ex(ctx, cipher + *outlen, &tmplen)) {
        fprintf(stderr, "ERROR: EVP_EncryptFinal_ex failed.\nOpenSSL Error: %s\n",
                ERR_error_string(ERR_get_error(), NULL));
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    *outlen += tmplen;

    EVP_CIPHER_CTX_free(ctx);

    return 1;
}

void gmp_assign_first_permutation(mpz_t perm, size_t mismatches) {
    // Set perm to first key
    // Equivalent to: (perm << mismatches) - 1
    mpz_set_ui(perm, 1);
    mpz_mul_2exp(perm, perm, mismatches);
    mpz_sub_ui(perm, perm, 1);
}

void gmp_assign_last_permutation(mpz_t perm, size_t mismatches, size_t key_size) {
    // First set the value to the first permutation.
    gmp_assign_first_permutation(perm, mismatches);
    // Equivalent to: perm << ((key_size * 8) - mismatches)
    // E.g. if key_size = 32 and mismatches = 5, then there are 256-bits
    // Then we want to shift left 256 - 5 = 251 times.
    mpz_mul_2exp(perm, perm, (key_size * 8) - mismatches);
}