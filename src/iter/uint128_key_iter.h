#ifndef UINT128_KEY_ITER_H
#define UINT128_KEY_ITER_H

#include <stddef.h>
#include <stdbool.h>

typedef struct uint128_key_iter {
    // Private members
    unsigned __int128 curr_perm;
    unsigned __int128 last_perm;
    unsigned __int128 t;
    unsigned __int128 key_uint;
    unsigned __int128 corrupted_key_uint;
    bool overflow;
} uint128_key_iter;

/// Allocate and initialize a iterator based on the parameters passed in.
/// \param key The original, starting key to work with.
/// \param first_perm The starting permutation.
/// \param last_perm The final permutation (where to stop the iterator).
/// \return Returns a memory allocated pointer to a uint128_key_iter, or NULL if something went wrong.
uint128_key_iter* uint128_key_iter_create(const unsigned char *key, unsigned __int128 first_perm,
        unsigned __int128 last_perm);
/// Deallocate a passed in iterator.
/// \param iter A pointer to an iterator. Passing in a NULL pointer is undefined behavior.
void uint128_key_iter_destroy(uint128_key_iter *iter);

/// Iterate forward to the next corrupted key.
/// \param iter A pointer to an iterator. Its internal state will be changed.
/// Passing in a NULL pointer is undefined behavior.
void uint128_key_iter_next(uint128_key_iter *iter);
/// Get the current corrupted key.
/// \param iter A pointer to an iterator that won't be modified.
/// Passing in a NULL pointer is undefined behavior.
/// \param corrupted_key The buffer to fill the corrupted key. Must have at least 16 bytes allocated
void uint128_key_iter_get(const uint128_key_iter *iter, unsigned char *corrupted_key);

/// Return a boolean value of whether the iterator has reached the end or not.
/// \param iter A pointer to an iterator that won't be modified.
/// Passing in a NULL pointer is undefined behavior.
/// \return Returns a 0 if the iterator hasn't reached the end, or a 1 if it has.
bool uint128_key_iter_end(const uint128_key_iter *iter);

#endif // UINT128_PERM_ITER_H
