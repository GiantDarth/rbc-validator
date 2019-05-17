#ifndef UINT64_KEY_ITER_H
#define UINT64_KEY_ITER_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

typedef struct uint64_key_iter {
    // Private members
    uint_fast64_t curr_perm;
    uint_fast64_t last_perm;
    uint_fast64_t t;
    uint_fast64_t key_uint;
    uint_fast64_t corrupted_key_uint;
    bool overflow;
} uint64_key_iter;

/// Allocate and initialize a iterator based on the parameters passed in.
/// \param key The original, starting key to work with.
/// \param first_perm The starting permutation.
/// \param last_perm The final permutation (where to stop the iterator).
/// \return Returns a memory allocated pointer to a uint64_key_iter, or NULL if something went wrong.
uint64_key_iter* uint64_key_iter_create(const unsigned char *key, uint_fast64_t first_perm,
        uint_fast64_t last_perm);
/// Deallocate a passed in iterator.
/// \param iter A pointer to an iterator. Passing in a NULL pointer is undefined behavior.
void uint64_key_iter_destroy(uint64_key_iter *iter);

/// Iterate forward to the next corrupted key.
/// \param iter A pointer to an iterator. Its internal state will be changed.
/// Passing in a NULL pointer is undefined behavior.
void uint64_key_iter_next(uint64_key_iter *iter);

/// Get the current corrupted key.
/// \param iter A pointer to an iterator that won't be modified.
/// Passing in a NULL pointer is undefined behavior.
/// \param corrupted_key The buffer to fill the corrupted key. Must have at least 8 bytes allocated.
void uint64_key_iter_get(const uint64_key_iter *iter, unsigned char *corrupted_key);
/// Get the current corrupted key.
/// \param iter A pointer to an iterator that won't be modified.
/// Passing in a NULL pointer is undefined behavior.
/// \param corrupted_key The buffer to fill the corrupted key. Must have at least 4 bytes allocated.
void uint32_key_iter_get(const uint64_key_iter *iter, unsigned char *corrupted_key);
/// Get the current corrupted key.
/// \param iter A pointer to an iterator that won't be modified.
/// Passing in a NULL pointer is undefined behavior.
/// \param corrupted_key The buffer to fill the corrupted key. Must have at least 2 bytes allocated.
void uint16_key_iter_get(const uint64_key_iter *iter, unsigned char *corrupted_key);
/// Get the current corrupted key.
/// \param iter A pointer to an iterator that won't be modified.
/// Passing in a NULL pointer is undefined behavior.
/// \param corrupted_key The buffer to fill the corrupted key. Must have at least 1 byte allocated.
void uint8_key_iter_get(const uint64_key_iter *iter, unsigned char *corrupted_key);

/// Return a boolean value of whether the iterator has reached the end or not.
/// \param iter A pointer to an iterator that won't be modified.
/// Passing in a NULL pointer is undefined behavior.
/// \return Returns a 0 if the iterator hasn't reached the end, or a 1 if it has.
bool uint64_key_iter_end(const uint64_key_iter *iter);
/// Return a boolean value of whether the iterator has reached the end or not.
/// \param iter A pointer to an iterator that won't be modified.
/// Passing in a NULL pointer is undefined behavior.
/// \return Returns a 0 if the iterator hasn't reached the end, or a 1 if it has.
bool uint32_key_iter_end(const uint64_key_iter *iter);
/// Return a boolean value of whether the iterator has reached the end or not.
/// \param iter A pointer to an iterator that won't be modified.
/// Passing in a NULL pointer is undefined behavior.
/// \return Returns a 0 if the iterator hasn't reached the end, or a 1 if it has.
bool uint16_key_iter_end(const uint64_key_iter *iter);
/// Return a boolean value of whether the iterator has reached the end or not.
/// \param iter A pointer to an iterator that won't be modified.
/// Passing in a NULL pointer is undefined behavior.
/// \return Returns a 0 if the iterator hasn't reached the end, or a 1 if it has.
bool uint8_key_iter_end(const uint64_key_iter *iter);

#endif // UINT64_PERM_ITER_H
