//
// Created by cp723 on 2/7/2019.
//

#ifndef HAMMING_BENCHMARK_UTIL_H
#define HAMMING_BENCHMARK_UTIL_H

#include <gmp.h>
#include <stdio.h>

#include "uint256_t.h"

/// Generate a random key using GMP's pseudo-random number generator functionality.
/// \param key A pre-allocated array that is key_size bytes long.
/// \param key_size The # of bytes to write to @param key.
/// \param randstate A GMP randomstate object that's pre-initialized and seeded.
void get_random_key(unsigned char *key, size_t key_size, gmp_randstate_t randstate);
/// Generate a randomly corrupted key based on a pre-existing key using GMP's pseudo-random number
/// generator functionality.
/// \param corrupted_key A pre-allocated array that is key_size bytes long. The final output of the
/// corrupted key.
/// \param key A pre-allocated array that is key_size bytes long. The starting key that will be corrupted
/// and saved to @param corrupted_key.
/// \param mismatches The # of bits to randomly flip form @param key written to @param corrupted_key.
/// \param key_size The # of bytes to read from @param key and write to @param corrupted_key.
/// \param subkey_length The range of bits to corrupt starting from the most significant bit. Cannot
/// exceed @param key_size in bits.
/// \param randstate A GMP randomstate object that's pre-initialized and seeded.
/// \param benchmark If benchmark is non-zero, then generate a corrupted key 50% up the way of the
/// keyspace for one randomly chosen slot.
/// \param The total # of available slots (usually # of threads or # of ranks).
void get_random_corrupted_key(unsigned char *corrupted_key, const unsigned char *key, int mismatches,
                              size_t key_size, size_t subkey_length, gmp_randstate_t randstate,
                              int benchmark, int numcores);

/// Create a starting-ending pair of permutations based on total pairs expected and its index out of
/// them. Meant to be used to feed into a gmp_key_iter.
/// \param starting_perm A pre-allocated mpz_t to fill the starting permutation to.
/// \param ending_perm A pre-allocated mpz_t to fill the ending permutation to.
/// \param pair_index A zero-based index out of all the possible pairs expected. Cannot exceed
/// @param pair_count.
/// \param pair_count The total amount of pairs expected to generate.
/// \param mismatches The hamming distance that you want to base the permutation on.
/// \param key_size How big the relevant entire key is in # of bytes.
/// \param subkey_length How big the only the potentially corruption portion is in bits, starting from
/// the most-significant bit.
void gmp_get_perm_pair(mpz_t starting_perm, mpz_t ending_perm, size_t pair_index, size_t pair_count,
                   int mismatches, size_t key_size, size_t subkey_length);

void uint256_get_perm_pair(uint256_t *starting_perm, uint256_t *ending_perm, size_t pair_index,
                           size_t pair_count, int mismatches, size_t key_size, size_t subkey_length);

/// Print out a raw byte array as hexadecimal.
/// \param stream An IO stream to output to.
/// \param array An allocated byte array to print.
/// \param count The # of bytes to print from array.
void fprint_hex(FILE *stream, const unsigned char *array, size_t count);
/// Unparse a hex string to a byte array. The hex string is assumed to be null-terminated.
/// \param array An allocated byte array to parse to.
/// \param hex_string A null-terminated hex string.
/// \return Returns 0 on success, 1 if the string contains any invalid characters, or 2
/// if the hex string length is odd.
int parse_hex(unsigned char *array, char *hex_string);

#endif //HAMMING_BENCHMARK_UTIL_H
