//
// Created by cp723 on 2/7/2019.
//

#include "util.h"

#include <openssl/err.h>
#include <openssl/evp.h>

void decode_ordinal(mpz_t perm, const mpz_t ordinal, size_t mismatches, size_t key_size) {
    mpz_t binom, curr_ordinal;
    mpz_inits(binom, curr_ordinal, NULL);

    mpz_set(curr_ordinal, ordinal);

    mpz_set_ui(perm, 0);
    for (unsigned long bit = key_size * 8 - 1; mismatches > 0; bit--)
    {
        mpz_bin_uiui(binom, bit, mismatches);
        if (mpz_cmp(curr_ordinal, binom) >= 0)
        {
            mpz_sub(curr_ordinal, curr_ordinal, binom);
            mpz_setbit(perm, bit);
            mismatches--;
        }
    }

    mpz_clears(binom, curr_ordinal, NULL);
}

void get_random_permutation(mpz_t perm, size_t mismatches, size_t key_size, gmp_randstate_t randstate, int numcores) {

    mpz_t ordinal, binom, rank, cores;
    mpz_inits(ordinal, binom, rank, NULL);
    mpz_init_set_ui(cores,numcores);

    mpz_bin_uiui(binom, key_size * 8, mismatches);

      //gmp_printf("binom is: %Zu\n", binom);
    // Choose a random rank from 0 to numcores - 1
    mpz_urandomm(rank,randstate,cores);

    //gmp_printf("Random rank first is: %Zu\n", rank);

    mpz_mul_ui(rank, rank, 2);
    mpz_add_ui(rank,rank, 1);
    mpz_mul(ordinal, binom, rank);

    // numcores * 2
    //mpz_mul_ui(cores, cores, 2);
    // good , mpz_tdiv_q(ordinal, binom, rank);

    //gmp_printf("Ordinal before is: %Zu\n", ordinal);
    mpz_tdiv_q_ui(ordinal, ordinal, numcores * 2);

    //gmp_printf("Ordinal after is: %Zu\n", ordinal);
    decode_ordinal(perm, ordinal, mismatches, key_size);

    //gmp_printf("Perm is: %#40Zx\n", perm);
    mpz_clears(ordinal, binom, rank, cores, NULL);
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

int encryptMsg(const unsigned char *key, const unsigned char *msg, size_t msgLen, unsigned char *cipher, int *outlen) {
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

void get_random_key(unsigned char *key, size_t key_size, gmp_randstate_t randstate) {
    mpz_t key_mpz;
    mpz_init(key_mpz);

    mpz_urandomb(key_mpz, randstate, key_size * 8);

    mpz_export(key, NULL, sizeof(*key), 1, 0, 0, key_mpz);

    mpz_clear(key_mpz);
}

void get_random_corrupted_key(unsigned char *corrupted_key, const unsigned char *key, size_t mismatches,
                              size_t key_size, gmp_randstate_t randstate, int numcores) {
    mpz_t key_mpz, corrupted_key_mpz, perm;
    mpz_inits(key_mpz, corrupted_key_mpz, perm, NULL);

    get_random_permutation(perm, mismatches, key_size, randstate, numcores);

    mpz_import(key_mpz, key_size, 1, sizeof(*key), 0, 0, key);

    // Perform an XOR operation between the permutation and the key.
    // If a bit is set in permutation, then flip the bit in the key.
    // Otherwise, leave it as is.
    mpz_xor(corrupted_key_mpz, key_mpz, perm);

    mpz_export(corrupted_key, NULL, sizeof(*corrupted_key), 1, 0, 0, corrupted_key_mpz);

    mpz_clears(key_mpz, corrupted_key_mpz, perm, NULL);
}

void get_perm_pair(mpz_t starting_perm, mpz_t ending_perm, size_t pair_index, size_t pair_count,
                   size_t mismatches, size_t key_size) {
    mpz_t total_perms, starting_ordinal, ending_ordinal;
    mpz_inits(total_perms, starting_ordinal, ending_ordinal, NULL);

    mpz_bin_uiui(total_perms, key_size * 8, mismatches);

    if(pair_index == 0) {
        gmp_assign_first_permutation(starting_perm, mismatches);
    }
    else {
        mpz_tdiv_q_ui(starting_ordinal, total_perms, pair_count);
        mpz_mul_ui(starting_ordinal, starting_ordinal, pair_index);

        decode_ordinal(starting_perm, starting_ordinal, mismatches, key_size);
    }

    if(pair_index == pair_count - 1) {
        gmp_assign_last_permutation(ending_perm, mismatches, key_size);
    }
    else {
        mpz_tdiv_q_ui(ending_ordinal, total_perms, pair_count);
        mpz_mul_ui(ending_ordinal, ending_ordinal, pair_index + 1);

        decode_ordinal(ending_perm, ending_ordinal, mismatches, key_size);
    }

    mpz_clears(total_perms, starting_ordinal, ending_ordinal, NULL);
}

void print_hex(unsigned char *array, size_t count) {
    for(size_t i = 0; i < count; i++) {
        printf("%02x", array[i]);
    }
}
