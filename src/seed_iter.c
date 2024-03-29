//
// Created by cp723 on 2/1/2019.
//

#include "seed_iter.h"

#include <string.h>

void mpn_overflowingRshift(mp_limb_t* rop, const mp_limb_t* op1, mp_size_t n, unsigned int shift);

int SeedIter_init(SeedIter* iter, const unsigned char* seed, size_t seed_size,
                  const mpz_t first_perm, const mpz_t last_perm) {
    if (iter == NULL || seed == NULL || seed_size > SEED_SIZE) {
        return 1;
    }

    memset(iter, 0, sizeof(*iter));

    mpn_copyi(iter->curr_perm, mpz_limbs_read(first_perm), mpz_size(first_perm));
    mpn_copyi(iter->last_perm, mpz_limbs_read(last_perm), mpz_size(last_perm));

    memcpy(iter->seed_mpn, seed, seed_size);

    // Perform an XOR operation between the permutation and the key.
    // If a bit is set in permutation, then flip the bit in the key.
    // Otherwise, leave it as is.
    mpn_xor_n(iter->corrupted_seed_mpn, iter->seed_mpn, iter->curr_perm, ITER_LIMB_SIZE);

    return 0;
}

void SeedIter_next(SeedIter* iter) {
    // Equivalent to: t = perm | (perm - 1)
    mpn_sub_1(iter->t, iter->curr_perm, ITER_LIMB_SIZE, 1);
    mpn_ior_n(iter->t, iter->t, iter->curr_perm, ITER_LIMB_SIZE);

    // Equivalent to: perm = (t + 1) | (((~t & -~t) - 1) >> (__builtin_ctz(perm) + 1))
    unsigned int shift;
    if (mpn_zero_p(iter->curr_perm, ITER_LIMB_SIZE)) {
        shift = (mp_bits_per_limb * ITER_LIMB_SIZE) + 1;
    } else {
        shift = mpn_scan1(iter->curr_perm, 0) + 1;
    }
    mpn_com(iter->curr_perm, iter->t, ITER_LIMB_SIZE);
    mpn_neg(iter->tmp, iter->curr_perm, ITER_LIMB_SIZE);
    mpn_and_n(iter->curr_perm, iter->curr_perm, iter->tmp, ITER_LIMB_SIZE);
    mpn_sub_1(iter->curr_perm, iter->curr_perm, ITER_LIMB_SIZE, 1);

    // Right shift by the ctz + 1
    mpn_overflowingRshift(iter->curr_perm, iter->curr_perm, ITER_LIMB_SIZE, shift);

    // This is the only portion that can potentially overflow
    iter->overflow = mpn_add_1(iter->t, iter->t, ITER_LIMB_SIZE, 1);
    mpn_ior_n(iter->curr_perm, iter->curr_perm, iter->t, ITER_LIMB_SIZE);

    // Perform an XOR operation between the permutation and the key.
    // If a bit is set in permutation, then flip the bit in the key.
    // Otherwise, leave it as is.
    mpn_xor_n(iter->corrupted_seed_mpn, iter->seed_mpn, iter->curr_perm, ITER_LIMB_SIZE);
}

const unsigned char* SeedIter_get(const SeedIter* iter) {
    return (const unsigned char*)iter->corrupted_seed_mpn;
}

void mpn_overflowingRshift(mp_limb_t* rop, const mp_limb_t* op1, mp_size_t n, unsigned int shift) {
    if (shift >= mp_bits_per_limb) {
        unsigned int limb_shifts = shift / mp_bits_per_limb;
        for (int i = (int)limb_shifts; i < n; ++i) {
            rop[i - limb_shifts] = op1[i];
        }

        // Zero out the leading limbs
        memset(&(rop[n - limb_shifts]), 0, limb_shifts * sizeof(mp_limb_t));
        shift %= mp_bits_per_limb;
    }

    if (shift > 0) {
        mpn_rshift(rop, op1, n, shift);
    }
}