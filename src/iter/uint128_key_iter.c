#include "uint128_key_iter.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "../util.h"

uint128_key_iter* uint128_key_iter_create(const unsigned char *key, unsigned __int128 first_perm,
        unsigned __int128 last_perm) {
    uint128_key_iter *iter;
    if((iter = calloc(1, sizeof(uint128_key_iter))) == NULL) {
        return NULL;
    }

    iter->curr_perm = first_perm;
    iter->last_perm = last_perm;

    // Copy key bytes to unsigned __int128
    iter->key_uint = *(unsigned __int128*)(key);

    // Perform an XOR operation between the permutation and the key.
    // If a bit is set in permutation, then flip the bit in the key.
    // Otherwise, leave it as is.
    iter->corrupted_key_uint = iter->key_uint ^ iter->curr_perm;

    return iter;
}

void uint128_key_iter_destroy(uint128_key_iter *iter) {
    free(iter);
}

void uint128_key_iter_next(uint128_key_iter *iter) {
    // Equivalent to: t = (perm | (perm - 1)) + 1
    iter->overflow = __builtin_add_overflow(iter->curr_perm | (iter->curr_perm - 1), 1, &(iter->t));

    // Equivalent to: perm = t | ((((t & -t) / (perm & -perm)) >> 1) - 1)
    iter->curr_perm = iter->t | (((iter->t & -(iter->t)) / (iter->curr_perm & -(iter->curr_perm)) >> 1) - 1);

    // Perform an XOR operation between the permutation and the key.
    // If a bit is set in permutation, then flip the bit in the key.
    // Otherwise, leave it as is.
    iter->corrupted_key_uint = iter->key_uint | iter->curr_perm;
}

void uint128_key_iter_get(const uint128_key_iter *iter, unsigned char* corrupted_key) {
    unsigned __int128 corrupted_key_uint = iter->corrupted_key_uint;
    for(int i = 0; i < sizeof(corrupted_key_uint); i++) {
        corrupted_key[i] = corrupted_key_uint & 0xff;
        corrupted_key_uint >>= 8;
    }
}

bool uint128_key_iter_end(const uint128_key_iter *iter) {
    return iter->curr_perm > iter->last_perm || iter->overflow;
}