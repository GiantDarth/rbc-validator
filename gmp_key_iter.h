//
// Created by cp723 on 2/1/2019.
//

#ifndef GMP_KEY_ITER_H
#define GMP_KEY_ITER_H

#include <gmp.h>

struct gmp_key_iter {
    // Private members
    mpz_t curr_perm;
    mpz_t last_perm;
    mpz_t t;
    mpz_t tmp;
    mpz_t next_perm;
    mpz_t key_mpz;
    mpz_t corrupted_key_mpz;
};

typedef struct gmp_key_iter gmp_key_iter;

void gmp_key_iter_create(gmp_key_iter *iter, const unsigned char *key, size_t key_size,
        const mpz_t first_perm, const mpz_t last_perm);
void gmp_key_iter_destroy(gmp_key_iter *iter);

void gmp_key_iter_next(gmp_key_iter *iter);
int gmp_key_iter_check(const gmp_key_iter *iter);
void gmp_key_iter_get(gmp_key_iter *iter, unsigned char *corrupted_key);

/// Assigns the first possible permutation for a given # of mismatches.
/// \param perm A pre-allocated mpz_t to fill the permutation to.
/// \param mismatches The hamming distance that you want to base the permutation on.
void gmp_assign_first_permutation(mpz_t perm, size_t mismatches);

/// Assigns the first possible permutation for a given # of mismatches and key size
/// \param perm A pre-allocated mpz_t to fill the permutation to.
/// \param mismatches The hamming distance that you want to base the permutation on.
/// \param key_size How big the relevant key is in # of bytes.
void gmp_assign_last_permutation(mpz_t perm, size_t mismatches, size_t key_size);

/// Use simple insertion sort to sort the permutations.
/// \param perms A pre-allocated array of permutations. This will be swapped in-place.
/// \param perms_size How big the array is.
void gmp_sort_permutations(mpz_t *perms, size_t perms_size);

#endif // GMP_PERM_ITER_H
