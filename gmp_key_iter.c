//
// Created by cp723 on 2/1/2019.
//

#include "gmp_key_iter.h"

#include <stdlib.h>

gmp_key_iter* gmp_key_iter_create(const unsigned char *key, size_t key_size,
        const mpz_t first_perm, const mpz_t last_perm) {
    gmp_key_iter *iter;
    if((iter = malloc(sizeof(*iter))) == NULL) {
        return NULL;
    }

    mpz_inits(iter->curr_perm, iter->last_perm, iter->t, iter->tmp, iter->key_mpz,
            iter->corrupted_key_mpz, NULL);

    mpz_set(iter->curr_perm, first_perm);
    mpz_set(iter->last_perm, last_perm);

    mpz_import(iter->key_mpz, key_size, 1, sizeof(*key), 0, 0, key);

    return iter;
}

void gmp_key_iter_destroy(gmp_key_iter *iter) {
    mpz_clears(iter->curr_perm, iter->last_perm, iter->t, iter->tmp, iter->key_mpz,
            iter->corrupted_key_mpz, NULL);
    free(iter);
}

void gmp_key_iter_next(gmp_key_iter *iter) {
    // Equivalent to: t = (perm | (perm - 1)) + 1
    mpz_sub_ui(iter->t, iter->curr_perm, 1);
    mpz_ior(iter->t, iter->curr_perm, iter->t);
    mpz_add_ui(iter->t, iter->t, 1);

    // Equivalent to: perm = t | ((((t & -t) / (perm & -perm)) >> 1) - 1)
    mpz_neg(iter->tmp, iter->curr_perm);
    mpz_and(iter->curr_perm, iter->curr_perm, iter->tmp);

    mpz_neg(iter->tmp, iter->t);
    mpz_and(iter->tmp, iter->t, iter->tmp);

    // Truncate divide
    mpz_tdiv_q(iter->tmp, iter->tmp, iter->curr_perm);
    // Right shift by 1
    mpz_tdiv_q_2exp(iter->tmp, iter->tmp, 1);
    mpz_sub_ui(iter->tmp, iter->tmp, 1);
    mpz_ior(iter->curr_perm, iter->t, iter->tmp);

    // Perform an XOR operation between the permutation and the key.
    // If a bit is set in permutation, then flip the bit in the key.
    // Otherwise, leave it as is.
    mpz_xor(iter->corrupted_key_mpz, iter->key_mpz, iter->curr_perm);
}

void gmp_key_iter_get(const gmp_key_iter *iter, unsigned char *corrupted_key) {
    // Convert from mpz to an unsigned char array
    mpz_export(corrupted_key, NULL, sizeof(*corrupted_key), 1, 0, 0, iter->corrupted_key_mpz);
}
