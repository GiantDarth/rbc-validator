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

void int_progression(size_t mismatches) {
    // Starting mismatch key
    unsigned int perm = (1 << mismatches) - 1, t;

    // printf("%u\n", perm);
    while(__builtin_ctz(perm) < (sizeof(perm) * 8) - mismatches) {
        t = perm | (perm - 1); // t gets v's least significant 0 bits set to 1
        // Next set to 1 the most significant bit to change, 
        // set to 0 the least significant ones, and add the necessary 1 bits.
        perm = (t + 1) | (((~t & -~t) - 1) >> (__builtin_ctz(perm) + 1));

        t = (perm | (perm - 1)) + 1;  
        perm = t | ((((t & -t) / (perm & -perm)) >> 1) - 1);  

        // printf("%u\n", perm);
    }
}

/// Given a starting permutation, iterate forward through every possible permutation until one that's matching
/// last_perm is found. With each new permutation, encrypt the given userId.
/// \param starting_perm The permutation to start iterating from.
/// \param last_perm The final permutation to stop iterating at, inclusively.
/// \param key The original AES key.
/// \param key_size The key size in # of bytes, typically 32.
/// \param userId A uuid_t that's used to as the message to encrypt.
void gmp_progression(const mpz_t starting_perm, const mpz_t last_perm, const unsigned char *key,
        size_t key_size, uuid_t userId) {
    unsigned char *corrupted_key;
    unsigned char cipher[sizeof(userId) + EVP_MAX_BLOCK_LENGTH];
    int outlen;

    // Initialization
    gmp_key_iter iter;
    gmp_key_iter_create(&iter, key, key_size, starting_perm, last_perm);

    // Memory allocation
    corrupted_key = malloc(sizeof(*corrupted_key) * key_size);

    // While we haven't reached the end of iteration
    while(!gmp_key_iter_end(&iter)) {
        gmp_key_iter_get(&iter, corrupted_key);
        // If encryption fails for some reason, break prematurely.
        if(!encrypt(corrupted_key, userId, sizeof(userId), cipher, &outlen)) {
            break;
        }

        gmp_key_iter_next(&iter);
    }

    // Cleanup
    free(corrupted_key);
    gmp_key_iter_destroy(&iter);
}

int main() {
    const size_t KEY_SIZE = 32;
    const size_t MISMATCHES = 4;

    unsigned char *key;
    key = malloc(sizeof(*key) * KEY_SIZE);

    size_t starting_perms_size = 512ULL;

    mpz_t *starting_perms;
    starting_perms = malloc(sizeof(*starting_perms) * starting_perms_size);
    for(size_t i = 0; i < starting_perms_size; i++) {
        mpz_init(starting_perms[i]);
    }

    mpz_t last_perm;
    mpz_init(last_perm);
    gmp_assign_last_permutation(last_perm, MISMATCHES, KEY_SIZE);

    generate_starting_permutations(starting_perms, starting_perms_size, MISMATCHES, KEY_SIZE);

    uuid_t userId;
    char uuid[37];

    uuid_generate(userId);
    uuid_unparse(userId, uuid);
    printf("Using UUID: %s\n", uuid);

    double startTime = omp_get_wtime();
    // int_progression(MISMATCHES);
    // Loop through every starting_perms, assuming that the array is already sorted.
    // Apparently the loop variable needs to be declared first and set as 'private(n)' for pure C?
    // (Needs to be checked on)
    size_t n;
    #pragma omp parallel for private(n) schedule(dynamic)
    for(n = 0; n < starting_perms_size; n++) {
        // If not the last of the starting_perms, set the last_perm to be the next item in the array
        if(n < starting_perms_size - 1) {
            gmp_progression(starting_perms[n], starting_perms[n + 1], key, KEY_SIZE, userId);
        }
            // Else, assume the last starting_perm will continue until last_perm.
        else {
            gmp_progression(starting_perms[n], last_perm, key, KEY_SIZE, userId);
        }
    }

    double duration = omp_get_wtime() - startTime;

    printf("Clock time: %f s\n", duration);

    mpz_clear(last_perm);
    for(size_t i = 0; i < starting_perms_size; i++) {
        mpz_clear(starting_perms[i]);
    }
    free(starting_perms);
    free(key);

    return 0;
}