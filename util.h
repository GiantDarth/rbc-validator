//
// Created by cp723 on 2/7/2019.
//

#ifndef HAMMING_BENCHMARK_UTIL_H
#define HAMMING_BENCHMARK_UTIL_H

#include <gmp.h>

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

#endif //HAMMING_BENCHMARK_UTIL_H
