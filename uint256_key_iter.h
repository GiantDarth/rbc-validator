//
// Created by cp723 on 2/1/2019.
//

#ifndef UINT256_KEY_ITER_H
#define UINT256_KEY_ITER_H

#include <stddef.h>

#include "uint256_t.h"

typedef struct uint256_key_iter {
    // Private members
    uint256_t curr_perm;
    uint256_t last_perm;
    uint256_t t;
    uint256_t tmp;
    uint256_t key_uint;
    uint256_t corrupted_key_uint;
} uint256_key_iter;

/// Allocate and initialize a iterator based on the parameters passed in.
/// \param iter A pointer to an iterator.
/// \param key The original, starting key to work with.
/// \param first_perm The starting permutation.
/// \param last_perm The final permutation (where to stop the iterator).
/// \return Returns a memory allocated pointer to a gmp_key_iter, or NULL if something went wrong.
uint256_key_iter* uint256_key_iter_create(const unsigned char *key, const uint256_t* first_perm,
        const uint256_t* last_perm);
/// Deallocate a passed in iterator.
/// \param iter A pointer to an iterator. Passing in a NULL pointer is undefined behavior.
void uint256_key_iter_destroy(uint256_key_iter *iter);

/// Iterate forward to the next corrupted key.
/// \param iter A pointer to an iterator. Its internal state will be changed.
/// Passing in a NULL pointer is undefined behavior.
void uint256_key_iter_next(uint256_key_iter *iter);
/// Get the current corrupted key.
/// \param iter A pointer to an iterator that won't be modified.
/// Passing in a NULL pointer is undefined behavior.
/// \param corrupted_key The buffer to fill the corrupted key. Must have at least 'key_size' bytes allocated
/// (based on gmp_key_iter_create)
void uint256_key_iter_get(const uint256_key_iter *iter, unsigned char *corrupted_key);

/// Return a boolean value of whether the iterator has reached the end or not.
/// \param iter A pointer to an iterator that won't be modified.
/// Passing in a NULL pointer is undefined behavior.
/// \return Returns a 0 if the iterator hasn't reached the end, or a 1 if it has.
int uint256_key_iter_end(const uint256_key_iter *iter);

#endif // UINT256_PERM_ITER_H
