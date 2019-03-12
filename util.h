//
// Created by cp723 on 2/7/2019.
//

#ifndef HAMMING_BENCHMARK_UTIL_H
#define HAMMING_BENCHMARK_UTIL_H

#include <gmp.h>
#include "uint256_t.h"

/// Based on https://cs.stackexchange.com/a/67669
/// \param perm The permutation to set.
/// \param ordinal The ordinal as the input.
/// \param mismatches How many bits to set.
/// \param key_size How big the bit string is (in bytes)
void decode_ordinal(mpz_t perm, const mpz_t ordinal, size_t mismatches, size_t key_size);

void get_random_permutation(mpz_t perm, size_t mismatches, size_t key_size, gmp_randstate_t randstate);

/// Generate a set of starting permutations based on mismatches and a maximum key_size.
/// \param starting_perms The pre-allocated, pre-initialized array of starting_perms to fill.
/// \param starting_perms_size The count of starting_perms.
/// \param mismatches The hamming distance to base on (equivalent to # of bits set).
/// \param key_size The # of bytes the permutations will be.
void generate_starting_permutations(mpz_t *starting_perms, size_t starting_perms_size, size_t mismatches,
                                    size_t key_size);

/// Encrypts some message data using AES-256-ECB w/ PCKS#7 padding
/// \param key The key data, must be at least 32 bytes long.
/// \param msg The message to be encrypted, designated to be msgLen bytes long.
/// \param msgLen Denotes the size of the message (not NULL-terminated).
/// \param cipher The output data's length (not NULL-terminated).
/// \return Returns 1 on success or 0 on error (typically OpenSSL error).
int encryptMsg(const unsigned char *key, const unsigned char *msg, size_t msgLen, unsigned char *cipher, int *outlen);

/// Assigns the first possible permutation for a given # of mismatches.
/// \param perm A pre-allocated mpz_t to fill the permutation to.
/// \param mismatches The hamming distance that you want to base the permutation on.
void gmp_assign_first_permutation(mpz_t perm, size_t mismatches);
/// Assigns the first possible permutation for a given # of mismatches and key size
/// \param perm A pre-allocated mpz_t to fill the permutation to.
/// \param mismatches The hamming distance that you want to base the permutation on.
/// \param key_size How big the relevant key is in # of bytes.
void gmp_assign_last_permutation(mpz_t perm, size_t mismatches, size_t key_size);

void uint256_assign_first_permutation(uint256_t *perm, size_t mismatches);
void uint256_assign_last_permutation(uint256_t *perm, size_t mismatches, size_t key_size);

/// Generate a random key using GMP's pseudo-random number generator functionality.
/// \param key A pre-allocated array that is key_size bytes long.
/// \param key_size The # of bytes to write to @param key.
/// \param randstate A GMP randomstate object that's pre-initialized and seeded.
void get_random_key(unsigned char *key, size_t key_size, gmp_randstate_t randstate);
/// Generate a randomly corrupted key based on a pre-existing key using GMP's pseudo-random number generator
/// functionality.
/// \param corrupted_key A pre-allocated array that is key_size bytes long. The final output of the corrupted key.
/// \param key A pre-allocated array that is key_size bytes long. The starting key that will be corrupted and
/// saved to @param corrupted_key.
/// \param mismatches The # of bits to randomly flip form @param key written to @param corrupted_key.
/// \param key_size The # of bytes to read from @param key and write to @param corrupted_key.
/// \param randstate A GMP randomstate object that's pre-initialized and seeded.
void get_random_corrupted_key(unsigned char *corrupted_key, const unsigned char *key, size_t mismatches,
                              size_t key_size, gmp_randstate_t randstate);

/// Create a starting-ending pair of permutations based on total pairs expected and its index out of them.
/// Meant to be used to feed into a gmp_key_iter.
/// \param starting_perm A pre-allocated mpz_t to fill the starting permutation to.
/// \param ending_perm A pre-allocated mpz_t to fill the ending permutation to.
/// \param pair_index A zero-based index out of all the possible pairs expected.
/// \param pair_count The total amount of pairs expected to generate.
/// \param mismatches The hamming distance that you want to base the permutation on.
/// \param key_size How big the relevant key is in # of bytes.
void gmp_get_perm_pair(mpz_t starting_perm, mpz_t ending_perm, size_t pair_index, size_t pair_count,
                   size_t mismatches, size_t key_size);

void uint256_get_perm_pair(uint256_t *starting_perm, uint256_t *ending_perm, size_t pair_index,
                           size_t pair_count, size_t mismatches, size_t key_size);

/// Print out a raw byte array as hexadecimal.
/// \param array An allocated byte array to print.
/// \param count The # of bytes to print from array.
void print_hex(const unsigned char *array, size_t count);

#endif //HAMMING_BENCHMARK_UTIL_H
