//
// Created by cp723 on 2/1/2019.
//

#ifndef RBC_VALIDATOR_SEED_ITER_H_
#define RBC_VALIDATOR_SEED_ITER_H_

#include <gmp.h>

#define SEED_SIZE 32
#define ITER_LIMB_SIZE (SEED_SIZE / sizeof(mp_limb_t))

typedef struct SeedIter {
    // Private members
    mp_limb_t overflow;
    mp_limb_t curr_perm[ITER_LIMB_SIZE];
    mp_limb_t last_perm[ITER_LIMB_SIZE];
    mp_limb_t t[ITER_LIMB_SIZE];
    mp_limb_t tmp[ITER_LIMB_SIZE];
    mp_limb_t seed_mpn[ITER_LIMB_SIZE];
    mp_limb_t corrupted_seed_mpn[ITER_LIMB_SIZE];
} SeedIter;

/// Initialize an iterator based on the parameters passed in.
/// \param iter A pointer to an iterator.
/// \param seed The original, starting key to work with.
/// \param seed_size How many characters (bytes) to read from the key.
/// \param first_perm The starting permutation.
/// \param last_perm The final permutation (where to stop the iterator).
/// \returns 0 for success, or 1 on error
int SeedIter_init(SeedIter* iter, const unsigned char* seed, size_t seed_size,
                  const mpz_t first_perm, const mpz_t last_perm);

/// Iterate forward to the next corrupted key.
/// \param iter A pointer to an iterator. Its internal state will be changed.
/// Passing in a NULL pointer is undefined behavior.
void SeedIter_next(SeedIter* iter);
/// Get the current corrupted key.
/// \param iter A pointer to an iterator that won't be modified.
/// Passing in a NULL pointer is undefined behavior.
/// \param corrupted_seed The buffer to fill the corrupted key. Must have at least 'key_size' bytes
/// allocated (based on gmp_seed_iter_create)
const unsigned char* SeedIter_get(const SeedIter* iter);

/// Return a boolean value of whether the iterator has reached the end or not.
/// \param iter A pointer to an iterator that won't be modified.
/// Passing in a NULL pointer is undefined behavior.
/// \return Returns a 0 if the iterator hasn't reached the end, or a 1 if it has.
static inline int SeedIter_end(const SeedIter* iter) {
    return iter->overflow || mpn_cmp(iter->curr_perm, iter->last_perm, ITER_LIMB_SIZE) > 0;
}

#endif  // RBC_VALIDATOR_SEED_ITER_H_
