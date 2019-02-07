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

/// Allocate and initialize a passed in iterator.
/// \param iter A pointer to an iterator.
/// \param key The original, starting key to work with.
/// \param key_size How many characters (bytes) to read from the key.
/// \param first_perm The starting permutation.
/// \param last_perm The final permutation (where to stop the iterator).
void gmp_key_iter_create(gmp_key_iter *iter, const unsigned char *key, size_t key_size,
        const mpz_t first_perm, const mpz_t last_perm);
/// Deallocate a passed in iterator.
/// \param iter A pointer to an iterator.
void gmp_key_iter_destroy(gmp_key_iter *iter);

/// Iterate forward to the next corrupted key.
/// \param iter A pointer to an iterator. Its internal state will be changed.
void gmp_key_iter_next(gmp_key_iter *iter);
/// Get the current corrupted key.
/// \param iter A pointer to an iterator that won't be modified.
/// \param corrupted_key The buffer to fill the corrupted key. Must have at least 'key_size' bytes allocated
/// (based on gmp_key_iter_create)
void gmp_key_iter_get(const gmp_key_iter *iter, unsigned char *corrupted_key);

/// Return a boolean value of whether the iterator has reached the end or not.
/// \param iter A pointer to an iterator that won't be modified.
/// \return Returns a 0 if the iterator hasn't reached the end, or a 1 if it has.
static inline int gmp_key_iter_end(const gmp_key_iter *iter) {
    return mpz_cmp(iter->curr_perm, iter->last_perm) > 0;
}

/// Assigns the first possible permutation for a given # of mismatches.
/// \param perm A pre-allocated mpz_t to fill the permutation to.
/// \param mismatches The hamming distance that you want to base the permutation on.
void gmp_assign_first_permutation(mpz_t perm, size_t mismatches);

/// Assigns the first possible permutation for a given # of mismatches and key size
/// \param perm A pre-allocated mpz_t to fill the permutation to.
/// \param mismatches The hamming distance that you want to base the permutation on.
/// \param key_size How big the relevant key is in # of bytes.
void gmp_assign_last_permutation(mpz_t perm, size_t mismatches, size_t key_size);

#endif // GMP_PERM_ITER_H
