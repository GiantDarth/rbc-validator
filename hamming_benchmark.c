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
/// \param signal A pointer to a shared value. Used to signal the function to prematurely leave.
/// \return Returns a 0 on success, or a -1 on an error.
int gmp_progression(const mpz_t starting_perm, const mpz_t last_perm, const unsigned char *key,
        size_t key_size, uuid_t userId, const int *signal) {
    unsigned char *corrupted_key;
    unsigned char cipher[EVP_MAX_BLOCK_LENGTH];
    int outlen;

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
    while(!gmp_key_iter_end(iter) && !(*signal)) {
        gmp_key_iter_get(iter, corrupted_key);
        // If encryption fails for some reason, break prematurely.
        if(!encryptMsg(corrupted_key, userId, sizeof(uuid_t), cipher, &outlen)) {
            // Cleanup
            gmp_key_iter_destroy(iter);
            free(corrupted_key);
            return -1;
        }

        gmp_key_iter_next(iter);
    }

    // Cleanup
    gmp_key_iter_destroy(iter);
    free(corrupted_key);

    return 0;
}

int main() {
    const size_t KEY_SIZE = 32;
    const size_t MISMATCHES = 3;
    // Use this line to manually set the # of threads, otherwise it detects it by your machine
//    omp_set_num_threads(4);

    uuid_t userId;
    char uuid_str[37];

    unsigned char *key;

    // Allocate memory
    if((key = malloc(sizeof(*key) * KEY_SIZE)) == NULL) {
        perror("Error");
        return EXIT_FAILURE;
    }

    // Initialize values
    uuid_generate(userId);

    // Convert the uuid to a string for printing
    uuid_unparse(userId, uuid_str);
    printf("Using UUID: %s\n", uuid_str);

    double startTime = omp_get_wtime();
    int signal = 0, error = 0;
    #pragma omp parallel
    {
        mpz_t starting_perm, ending_perm;
        mpz_inits(starting_perm, ending_perm, NULL);

        get_perm_pair(starting_perm, ending_perm, (size_t)omp_get_thread_num(), (size_t)omp_get_num_threads(),
                      MISMATCHES, KEY_SIZE);

        // If the result is non-zero, set a flag that an error has occurred, and stop the other threads.
        // Will cause the other threads to prematurely stop.
        if(gmp_progression(starting_perm, ending_perm, key, KEY_SIZE, userId, &signal)) {
            // Set the signal to stop the other threads
#pragma omp critical
            {
                error = 1;
                signal = 1;
            };
        }

        mpz_clears(starting_perm, ending_perm, NULL);
    }

    // Check if an error occurred in one of the threads.
    if(error) {
        // Cleanup
        free(key);

        return EXIT_FAILURE;
    }

    double duration = omp_get_wtime() - startTime;

    printf("Clock time: %f s\n", duration);

    // Cleanup
    free(key);

    return EXIT_SUCCESS;
}