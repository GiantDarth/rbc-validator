//
// Created by cp723 on 2/1/2019.
//

#include "uint256_key_iter.h"

#include <stdlib.h>
#include <stdio.h>

uint256_key_iter* uint256_key_iter_create(const unsigned char *key, const uint256_t *first_perm,
        const uint256_t *last_perm) {
    uint256_key_iter *iter;
    printf("%zu\n", sizeof(struct uint256_key_iter));
    if((iter = calloc(1, sizeof(uint256_key_iter))) == NULL) {
        return NULL;
    }

    iter->curr_perm = *first_perm;
    iter->last_perm = *last_perm;

    uint256_import(&(iter->key_uint), key);

    return iter;
}

void uint256_key_iter_destroy(uint256_key_iter *iter) {
    free(iter);
}

void uint256_key_iter_next(uint256_key_iter *iter) {
    // Equivalent to: t = perm | (perm - 1)
    uint256_add(&(iter->t), &(iter->curr_perm), &UINT256_NEG_ONE);
    uint256_ior(&(iter->t), &(iter->t), &(iter->curr_perm));

    // Equivalent to: perm = (t + 1) | (((~t & -~t) - 1) >> (__builtin_ctz(perm) + 1))
    unsigned long shift = uint256_ctz(&(iter->curr_perm)) + 1;
    uint256_com(&(iter->curr_perm), &(iter->t));
    uint256_neg(&(iter->tmp), &(iter->curr_perm));
    uint256_and(&(iter->tmp), &(iter->tmp), &(iter->curr_perm));
    uint256_add(&(iter->tmp), &(iter->tmp), &UINT256_NEG_ONE);

    uint256_shift_right(&(iter->tmp), &(iter->tmp), shift);

    iter->overflow = uint256_add(&(iter->t), &(iter->t), &UINT256_ONE);
    uint256_and(&(iter->tmp), &(iter->t), &(iter->tmp));

    uint256_ior(&(iter->curr_perm), &(iter->t), &(iter->tmp));

    // Perform an XOR operation between the permutation and the key.
    // If a bit is set in permutation, then flip the bit in the key.
    // Otherwise, leave it as is.
    uint256_xor(&(iter->corrupted_key_uint), &(iter->key_uint), &(iter->curr_perm));
}

void uint256_key_iter_get(const uint256_key_iter *iter, unsigned char *corrupted_key) {
    // Convert from mpz to an unsigned char array
    uint256_export(corrupted_key, &(iter->corrupted_key_uint));
}

int uint256_key_iter_end(const uint256_key_iter *iter) {
    return uint256_eq(&(iter->curr_perm), &(iter->last_perm)) || iter->overflow;
}