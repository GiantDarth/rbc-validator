//
// Created by cp723 on 2/7/2019.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

#include <openssl/evp.h>
#include <uuid/uuid.h>
#include <gmp.h>
#include <omp.h>

#include "gmp_key_iter.h"
#include "util.h"

void get_random_key(unsigned char *key, size_t key_size, gmp_randstate_t randstate) {
    mpz_t key_mpz;
    mpz_init(key_mpz);

    mpz_urandomb(key_mpz, randstate, key_size * 8);

    mpz_export(key, NULL, sizeof(*key), 1, 0, 0, key_mpz);

    mpz_clear(key_mpz);
}

void get_random_corrupted_key(const unsigned char *key, unsigned char *corrupted_key, size_t mismatches,
        size_t key_size, gmp_randstate_t randstate) {
    mpz_t key_mpz, corrupted_key_mpz, perm;
    mpz_inits(key_mpz, corrupted_key_mpz, perm, NULL);

    get_random_permutation(perm, mismatches, key_size, randstate);

    mpz_import(key_mpz, key_size, 1, sizeof(*key), 0, 0, key);

    // Perform an XOR operation between the permutation and the key.
    // If a bit is set in permutation, then flip the bit in the key.
    // Otherwise, leave it as is.
    mpz_xor(corrupted_key_mpz, key_mpz, perm);

    mpz_export(corrupted_key, NULL, sizeof(*corrupted_key), 1, 0, 0, corrupted_key_mpz);

    mpz_clears(key_mpz, corrupted_key_mpz, perm, NULL);
}

/// Given a starting permutation, iterate forward through every possible permutation until one that's matching
/// last_perm is found, or until a matching cipher is found.
/// \param starting_perm The permutation to start iterating from.
/// \param last_perm The final permutation to stop iterating at, inclusively.
/// \param key The original AES key.
/// \param key_size The key size in # of bytes, typically 32.
/// \param userId A uuid_t that's used to as the message to encrypt.
/// \param auth_cipher The authentication cipher to test against
/// \param global_found A pointer to a shared "found" variable so as to cut out early if another thread
/// has found it.
/// \return Returns a 1 if found or a 0 if not. Returns a -1 if an error has occurred.
int gmp_validator(const mpz_t starting_perm, const mpz_t last_perm, const unsigned char *key,
                     size_t key_size, uuid_t userId, const unsigned char *auth_cipher, const int* global_found) {
    // Declaration
    unsigned char *corrupted_key;
    unsigned char cipher[EVP_MAX_BLOCK_LENGTH];
    int outlen, found = 0;

    gmp_key_iter *iter;

    // Memory allocation
    if((corrupted_key = malloc(sizeof(*corrupted_key) * key_size)) == NULL) {
        perror("Error");
        return -1;
    }

    // Allocation and initialization
    if((iter = gmp_key_iter_create(key, key_size, starting_perm, last_perm)) == NULL) {
        perror("Error");
        free(corrupted_key);
        return -1;
    }

    // While we haven't reached the end of iteration
    while(!gmp_key_iter_end(iter) && !(*global_found)) {
        gmp_key_iter_get(iter, corrupted_key);
        // If encryption fails for some reason, break prematurely.
        if(!encrypt(corrupted_key, userId, sizeof(uuid_t), cipher, &outlen)) {
            break;
        }
        // If the new cipher is the same as the passed in auth_cipher, set found to true and break
        if(memcmp(cipher, auth_cipher, (size_t)outlen) == 0) {
            found = 1;
            break;
        }

        gmp_key_iter_next(iter);
    }

    // Cleanup
    gmp_key_iter_destroy(iter);
    free(corrupted_key);

    return found;
}

int main() {
    const size_t KEY_SIZE = 32;
    const size_t MISMATCHES = 4;
    size_t starting_perms_size = 512ULL;

    gmp_randstate_t randstate;

    uuid_t userId;
    char uuid_str[37];

    unsigned char *key;
    unsigned char *corrupted_key;
    unsigned char auth_cipher[EVP_MAX_BLOCK_LENGTH];

    mpz_t *starting_perms;
    mpz_t last_perm;

    // Memory allocation
    if((key = malloc(sizeof(*key) * KEY_SIZE)) == NULL) {
        perror("Error");
        return EXIT_FAILURE;
    }

    if((corrupted_key = malloc(sizeof(*corrupted_key) * KEY_SIZE)) == NULL) {
        perror("Error");
        free(key);
        return EXIT_FAILURE;
    }

    if((starting_perms = malloc(sizeof(*starting_perms) * starting_perms_size)) == NULL) {
        perror("Error");
        free(key);
        free(corrupted_key);
        return EXIT_FAILURE;
    }

    for(size_t i = 0; i < starting_perms_size; i++) {
        mpz_init(starting_perms[i]);
    }
    mpz_init(last_perm);

    // Initialize values
    uuid_generate(userId);
    uuid_unparse(userId, uuid_str);
    printf("Using UUID: %s\n", uuid_str);

    // Set the gmp prng algorithm and set a seed based on the current time
    gmp_randinit_default(randstate);
    gmp_randseed_ui(randstate, (unsigned long)time(NULL));

    get_random_key(key, KEY_SIZE, randstate);
    get_random_corrupted_key(key, corrupted_key, MISMATCHES, KEY_SIZE, randstate);

    int outlen;
    if(!encrypt(corrupted_key, userId, sizeof(userId), auth_cipher, &outlen)) {
        // Cleanup
        mpz_clear(last_perm);
        for(size_t i = 0; i < starting_perms_size; i++) {
            mpz_clear(starting_perms[i]);
        }
        free(starting_perms);
        free(corrupted_key);
        free(key);

        return EXIT_FAILURE;
    }

    generate_starting_permutations(starting_perms, starting_perms_size, MISMATCHES, KEY_SIZE);
    gmp_assign_last_permutation(last_perm, MISMATCHES, KEY_SIZE);

    double startTime = omp_get_wtime();
    // Loop through every starting_perms, assuming that the array is already sorted.
    // Apparently the loop variable needs to be declared first and set as 'private(n)' for pure C?
    // (Needs to be checked on)
    size_t n;
    int found = 0;
    #pragma omp parallel for private(n) schedule(dynamic)
    for(n = 0; n < starting_perms_size; n++) {
        // If already found
        if(!found) {
            // If not the last of the starting_perms, set the last_perm to be the next item in the array
            if(n < starting_perms_size - 1) {
                if(gmp_validator(starting_perms[n], starting_perms[n + 1], key, KEY_SIZE, userId,
                        auth_cipher, &found)) {
                    found = 1;
                }
            }
                // Else, assume the last starting_perm will continue until last_perm.
            else {
                if(gmp_validator(starting_perms[n], last_perm, key, KEY_SIZE, userId, auth_cipher,
                        &found)) {
                    found = 1;
                }
            }
        }
    }

    double duration = omp_get_wtime() - startTime;

    printf("Clock time: %f s\n", duration);

    printf("Found: %d", found);

    // Cleanup
    mpz_clear(last_perm);
    for(size_t i = 0; i < starting_perms_size; i++) {
        mpz_clear(starting_perms[i]);
    }
    free(starting_perms);
    free(corrupted_key);
    free(key);

    return 0;
}