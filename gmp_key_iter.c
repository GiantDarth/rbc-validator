//
// Created by cp723 on 2/1/2019.
//

#include "gmp_key_iter.h"

void gmp_key_iter_create(gmp_key_iter *iter, const unsigned char *key, size_t key_size,
        const mpz_t first_perm, const mpz_t last_perm) {
    mpz_inits(iter->curr_perm, iter->last_perm, iter->t, iter->tmp, iter->next_perm,
            iter->key_mpz, iter->corrupted_key_mpz, NULL);

    mpz_set(iter->curr_perm, first_perm);
    mpz_set(iter->last_perm, last_perm);

    mpz_import(iter->key_mpz, key_size, 1, sizeof(*key), 0, 0, key);
}


void gmp_key_iter_destroy(gmp_key_iter *iter) {
    mpz_clears(iter->curr_perm, iter->last_perm, iter->t, iter->tmp, iter->next_perm,
            iter->key_mpz, iter->corrupted_key_mpz, NULL);
}

void gmp_key_iter_next(gmp_key_iter *iter) {
    // Equivalent to: t = (perm | (perm - 1)) + 1
    mpz_sub_ui(iter->next_perm, iter->curr_perm, 1);
    mpz_ior(iter->t, iter->curr_perm, iter->next_perm);
    mpz_add_ui(iter->t, iter->t, 1);

    // Equivalent to: perm = t | ((((t & -t) / (perm & -perm)) >> 1) - 1)
    mpz_neg(iter->next_perm, iter->curr_perm);
    mpz_and(iter->next_perm, iter->curr_perm, iter->next_perm);

    mpz_neg(iter->tmp, iter->t);
    mpz_and(iter->tmp, iter->t, iter->tmp);

    // Truncate divide
    mpz_tdiv_q(iter->next_perm, iter->tmp, iter->next_perm);
    // Right shift by 1
    mpz_tdiv_q_2exp(iter->next_perm, iter->next_perm, 1);
    mpz_sub_ui(iter->next_perm, iter->next_perm, 1);
    mpz_ior(iter->curr_perm, iter->t, iter->next_perm);

    // Perform a NAND operation between the permutation and the key.
    // If a bit is set in permutation, then flip the bit in the key.
    // Otherwise, leave it as is.
    mpz_and(iter->corrupted_key_mpz, iter->key_mpz, iter->curr_perm);
    mpz_neg(iter->corrupted_key_mpz, iter->key_mpz);
}

int gmp_key_iter_check(const gmp_key_iter *iter) {
    return mpz_cmp(iter->curr_perm, iter->last_perm) > 0;
}

void gmp_key_iter_get(gmp_key_iter *iter, unsigned char *corrupted_key) {
    // Convert from mpz to an unsigned char array

    mpz_export(corrupted_key, NULL, sizeof(*corrupted_key), 1, 0, 0, iter->corrupted_key_mpz);
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
