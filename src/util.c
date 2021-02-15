#include "util.h"

#include <stdio.h>
#include <string.h>

/// Based on https://cs.stackexchange.com/a/67669
/// \param perm The permutation to set.
/// \param ordinal The ordinal as the input.
/// \param mismatches How many bits to set.
/// \param subkey_length How big the actual bit string is in bits
void decode_ordinal(mpz_t perm, const mpz_t ordinal, int mismatches, size_t subkey_length) {
    mpz_t binom, curr_ordinal;
    mpz_inits(binom, curr_ordinal, NULL);

    mpz_set(curr_ordinal, ordinal);

    mpz_set_ui(perm, 0);
    for (unsigned long bit = subkey_length - 1; mismatches > 0; bit--)
    {
        mpz_bin_uiui(binom, bit, mismatches);
        if (mpz_cmp(curr_ordinal, binom) >= 0)
        {
            mpz_sub(curr_ordinal, curr_ordinal, binom);
            mpz_setbit(perm, bit);
            mismatches--;
        }
    }

    mpz_clears(binom, curr_ordinal, NULL);
}

void get_random_permutation(mpz_t perm, int mismatches, size_t subkey_length,
        gmp_randstate_t randstate) {
    mpz_t ordinal, binom;
    mpz_inits(ordinal, binom, NULL);

    mpz_bin_uiui(binom, subkey_length, mismatches);

    mpz_urandomm(ordinal, randstate, binom);
    decode_ordinal(perm, ordinal, mismatches, subkey_length);

    mpz_clears(ordinal, binom, NULL);
}

void get_benchmark_permutation(mpz_t perm, int mismatches, size_t subkey_length,
        gmp_randstate_t randstate, int numcores) {
    mpz_t ordinal, binom, rank, cores;
    mpz_inits(ordinal, binom, rank, NULL);
    mpz_init_set_ui(cores, numcores);

    mpz_bin_uiui(binom, subkey_length, mismatches);

    // Choose a random rank from 0 to numcores - 1
    mpz_urandomm(rank, randstate, cores);

    mpz_mul_ui(rank, rank, 2);
    mpz_add_ui(rank, rank, 1);
    mpz_mul(ordinal, binom, rank);

    mpz_tdiv_q_ui(ordinal, ordinal, numcores * 2);

    decode_ordinal(perm, ordinal, mismatches, subkey_length);

    mpz_clears(ordinal, binom, rank, cores, NULL);
}

/// Assigns the first possible permutation for a given # of mismatches.
/// \param perm A pre-allocated mpz_t to fill the permutation to.
/// \param mismatches The hamming distance that you want to base the permutation on.
void gmp_assign_first_permutation(mpz_t perm, int mismatches) {
    // Set perm to first key
    // Equivalent to: (perm << mismatches) - 1
    mpz_set_ui(perm, 1);
    mpz_mul_2exp(perm, perm, mismatches);
    mpz_sub_ui(perm, perm, 1);
}

/// Assigns the first possible permutation for a given # of mismatches and key size
/// \param perm A pre-allocated mpz_t to fill the permutation to.
/// \param mismatches The hamming distance that you want to base the permutation on.
/// \param subkey_length How big the relevant key is in # of bits.
void gmp_assign_last_permutation(mpz_t perm, int mismatches, size_t subkey_length) {
    // First set the value to the first permutation.
    gmp_assign_first_permutation(perm, mismatches);
    // Equivalent to: perm << (subkey_length - mismatches)
    // E.g. if subkey_length = 256 and mismatches = 5
    // Then we want to shift left 256 - 5 = 251 times.
    mpz_mul_2exp(perm, perm, subkey_length - mismatches);
}

void uint256_assign_first_permutation(uint256_t *perm, int mismatches) {
    // Set perm to first key
    // Equivalent to: (perm << mismatches) - 1
    uint256_shift_left(perm, perm, (int)mismatches);
    uint256_add(perm, perm, &UINT256_NEG_ONE);
}

void uint256_assign_last_permutation(uint256_t *perm, int mismatches, size_t subkey_length) {
    // First set the value to the first permutation.
    uint256_assign_first_permutation(perm, mismatches);
    // Equivalent to: perm << (key_length - mismatches)
    // E.g. if key_length = 256 and mismatches = 5
    // Then we want to shift left 256 - 5 = 251 times.
    uint256_shift_left(perm, perm, (int)(subkey_length - mismatches));
}

void get_random_seed(unsigned char *key, size_t key_size, gmp_randstate_t randstate) {
    mpz_t key_mpz;
    mpz_init(key_mpz);

    mpz_urandomb(key_mpz, randstate, key_size * 8);

    mpz_export(key, NULL, sizeof(*key), 1, 0, 0, key_mpz);

    mpz_clear(key_mpz);
}

void get_random_corrupted_seed(unsigned char *corrupted_seed, const unsigned char *seed, int mismatches,
                               size_t subkey_length, gmp_randstate_t randstate,
                               int benchmark, int numcores) {
    mpz_t perm_mpz;
    uint256_t key_uint, corrupted_key_uint, perm_uint;

    mpz_init(perm_mpz);
    uint256_set_ui(&corrupted_key_uint, 0);

    if(benchmark) {
        get_benchmark_permutation(perm_mpz, mismatches, subkey_length, randstate, numcores);
    }
    else {
        get_random_permutation(perm_mpz, mismatches, subkey_length, randstate);
    }

    // Left shift permutation by (key_size * 8) - subkey_length bits to make it most significant bit
    // aligned.

    uint256_import(&key_uint, seed);
    uint256_from_mpz(&perm_uint, perm_mpz);

    // Perform an XOR operation between the permutation and the seed.
    // If a bit is set in permutation, then flip the bit in the seed.
    // Otherwise, leave it as is.
    uint256_xor(&corrupted_key_uint, &key_uint, &perm_uint);

    uint256_export(corrupted_seed, &corrupted_key_uint);

    mpz_clear(perm_mpz);
}

void gmp_get_perm_pair(mpz_t starting_perm, mpz_t ending_perm, size_t pair_index, size_t pair_count,
                   int mismatches, size_t subkey_length) {
    mpz_t total_perms, starting_ordinal, ending_ordinal;
    mpz_inits(total_perms, starting_ordinal, ending_ordinal, NULL);

    mpz_bin_uiui(total_perms, subkey_length, mismatches);

    if(pair_index == 0) {
        gmp_assign_first_permutation(starting_perm, mismatches);
    }
    else {
        mpz_tdiv_q_ui(starting_ordinal, total_perms, pair_count);
        mpz_mul_ui(starting_ordinal, starting_ordinal, pair_index);

        decode_ordinal(starting_perm, starting_ordinal, mismatches, subkey_length);
    }

    if(pair_index == pair_count - 1) {
        gmp_assign_last_permutation(ending_perm, mismatches, subkey_length);
    }
    else {
        mpz_tdiv_q_ui(ending_ordinal, total_perms, pair_count);
        mpz_mul_ui(ending_ordinal, ending_ordinal, pair_index + 1);

        decode_ordinal(ending_perm, ending_ordinal, mismatches, subkey_length);
    }

    // Left shift permutations by (key_size * 8) - subkey_length bits to make them most significant bit
    // aligned.

    mpz_clears(total_perms, starting_ordinal, ending_ordinal, NULL);
}

void uint256_get_perm_pair(uint256_t *starting_perm, uint256_t *ending_perm, size_t pair_index,
        size_t pair_count, int mismatches, size_t subkey_length) {
    mpz_t starting_perm_mpz, ending_perm_mpz;

    mpz_inits(starting_perm_mpz, ending_perm_mpz, NULL);

    gmp_get_perm_pair(starting_perm_mpz, ending_perm_mpz, pair_index, pair_count, mismatches,
            subkey_length);

    uint256_from_mpz(starting_perm, starting_perm_mpz);
    uint256_from_mpz(ending_perm, ending_perm_mpz);

    mpz_clears(starting_perm_mpz, ending_perm_mpz, NULL);
}

void fprint_hex(FILE *stream, const unsigned char *array, size_t count) {
    for(size_t i = 0; i < count; i++) {
        fprintf(stream, "%02x", array[i]);
    }
}

/// Parse an individual hexadecimal character to an integer 0 to 15.
/// \param hex_char An individual hexadecimal character.
/// \return Return 0 to 15 depending on the value of hex_char, else return -1 on an invalid character.
int parse_hex_char(char hex_char) {
    if(hex_char >= '0' && hex_char <= '9') {
        return hex_char - 48;
    }
    else if(hex_char >= 'A' && hex_char <= 'F') {
        return hex_char - 55;
    }
    else if(hex_char >= 'a' && hex_char <= 'f') {
        return hex_char - 87;
    }
    else {
        return -1;
    }
}

int parse_hex(unsigned char *array, char *hex_string) {
    size_t i, b;
    int value;

    for(i = 0, b = 0; hex_string[b] != '\0'; i++) {
        if((value = parse_hex_char(hex_string[b++])) < 0) {
            return 1;
        }

        array[i] = (unsigned char)value << 4;

        // The length of hex string was odd
        if(hex_string[b] == '\0') {
            return 2;
        }

        if((value = parse_hex_char(hex_string[b++])) < 0) {
            return 1;
        }

        array[i] |= (unsigned char)value;
    }

    return 0;
}
