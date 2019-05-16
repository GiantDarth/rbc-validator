//
// Created by cp723 on 2/1/2019.
//

#include "uint64_key_iter.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "../util.h"

uint64_key_iter* uint64_key_iter_create(const unsigned char *key, uint64_t first_perm,
        uint64_t last_perm) {
    uint64_key_iter *iter;
    if((iter = calloc(1, sizeof(uint64_key_iter))) == NULL) {
        return NULL;
    }

    iter->curr_perm = first_perm;
    iter->last_perm = last_perm;

    // Copy key bytes to uint64_t
    iter->key_uint = *(uint64_t*)(key);

    // Perform an XOR operation between the permutation and the key.
    // If a bit is set in permutation, then flip the bit in the key.
    // Otherwise, leave it as is.
    iter->corrupted_key_uint = iter->key_uint ^ iter->curr_perm;

    return iter;
}

void uint64_key_iter_destroy(uint64_key_iter *iter) {
    free(iter);
}

void uint64_key_iter_next(uint64_key_iter *iter) {
    // Equivalent to: t = perm | (perm - 1)
    iter->t = iter->curr_perm | (iter->curr_perm - 1);

    // Equivalent to: perm = (t + 1) | (((~t & -~t) - 1) >> (__builtin_ctz(perm) + 1))
    iter->curr_perm = ((~(iter->t) & -(~(iter->t))) - 1) >> ((iter->curr_perm != 0 ? __builtin_ctzll(iter->curr_perm) : 0) + 1);
    iter->overflow = __builtin_uaddll_overflow(iter->t, 1, &(iter->t));
    iter->curr_perm |= iter->t;

    // Perform an XOR operation between the permutation and the key.
    // If a bit is set in permutation, then flip the bit in the key.
    // Otherwise, leave it as is.
    iter->corrupted_key_uint = iter->key_uint | iter->curr_perm;
}

void uint64_key_iter_get(const uint64_key_iter *iter, unsigned char* corrupted_key) {
    uint64_t corrupted_key_uint = iter->corrupted_key_uint;
    for(int i = 0; i < sizeof(corrupted_key_uint); i++) {
        corrupted_key[i] = corrupted_key_uint & 0xff;
        corrupted_key_uint >>= 8;
    }
}

void uint32_key_iter_get(const uint64_key_iter *iter, unsigned char* corrupted_key) {
    uint32_t corrupted_key_uint = iter->corrupted_key_uint;
    for(int i = 0; i < sizeof(corrupted_key_uint); i++) {
        corrupted_key[i] = corrupted_key_uint & 0xff;
        corrupted_key_uint >>= 8;
    }
}

void uint16_key_iter_get(const uint64_key_iter *iter, unsigned char* corrupted_key) {
    corrupted_key[0] = iter->corrupted_key_uint & 0xff;
    corrupted_key[1] = (iter->corrupted_key_uint >> 8) & 0xff;
}

void uint8_key_iter_get(const uint64_key_iter *iter, unsigned char* corrupted_key) {
    corrupted_key[0] = iter->corrupted_key_uint & 0xff;
}

bool uint64_key_iter_end(const uint64_key_iter *iter) {
    return iter->curr_perm > iter->last_perm || iter->overflow;
}

bool uint32_key_iter_end(const uint64_key_iter *iter) {
    return iter->curr_perm > iter->last_perm || iter->curr_perm > UINT32_MAX;
}

bool uint16_key_iter_end(const uint64_key_iter *iter) {
    return iter->curr_perm > iter->last_perm || iter->curr_perm > UINT16_MAX;
}

bool uint8_key_iter_end(const uint64_key_iter *iter) {
    return iter->curr_perm > iter->last_perm || iter->curr_perm > UINT8_MAX;
}