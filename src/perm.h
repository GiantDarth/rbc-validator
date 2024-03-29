//
// Created by chaos on 3/4/2021.
//

#ifndef RBC_VALIDATOR_PERM_H_
#define RBC_VALIDATOR_PERM_H_

#include <gmp.h>

/// Generate a random key using GMP's pseudo-random number generator functionality.
/// \param key A pre-allocated array that is key_size bytes long.
/// \param key_size The # of bytes to write to @param key.
/// \param randstate A GMP randomstate object that's pre-initialized and seeded.
void getRandomSeed(unsigned char* key, size_t key_size, gmp_randstate_t randstate);

/// Generate a randomly corrupted seed based on a pre-existing seed using GMP's pseudo-random number
/// generator functionality.
/// \param corrupted_seed A pre-allocated array that is key_size bytes long. The final output of the
/// corrupted seed.
/// \param seed A pre-allocated array that is key_size bytes long. The starting seed that will be
/// corrupted and saved to @param corrupted_seed.
/// \param mismatches The # of bits to randomly flip form @param seed written to
/// @param corrupted_seed.
/// \param seed_size The # of bytes to read from @param seed and write to @param corrupted_seed.
/// \param subseed_length The range of bits to corrupt starting from the most significant bit.
/// Cannot exceed @param seed_size in bits.
/// \param randstate A GMP randomstate object that's pre-initialized and seeded.
/// \param benchmark If benchmark is non-zero, then generate a corrupted seed 50% up the way of the
/// keyspace for one randomly chosen slot.
/// \param numcores The total # of available slots (usually # of threads or # of
/// ranks).
void getRandomCorruptedSeed(unsigned char* corrupted_seed, const unsigned char* seed,
                            int mismatches, size_t seed_size, size_t subseed_length,
                            gmp_randstate_t randstate, int benchmark, int numcores);

/// Create a starting-ending pair of permutations based on total pairs expected and its index out of
/// them. Meant to be used to feed into a gmp_key_iter.
/// \param first_perm A pre-allocated mpz_t to fill the starting permutation to.
/// \param last_perm A pre-allocated mpz_t to fill the ending permutation to.
/// \param pair_index A zero-based index out of all the possible pairs expected. Cannot exceed
/// @param pair_count.
/// \param pair_count The total amount of pairs expected to generate.
/// \param mismatches The hamming distance that you want to base the permutation on.
/// \param key_size How big the relevant entire key is in # of bytes.
/// \param subkey_length How big the only the potentially corruption portion is in bits, starting
/// from the most-significant bit.
void getPermPair(mpz_t first_perm, mpz_t last_perm, size_t pair_index, size_t pair_count,
                 int mismatches, size_t subkey_length);

#endif  // RBC_VALIDATOR_PERM_H_
