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
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>

#include "gmp_key_iter.h"
#include "util.h"

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
                     size_t key_size, uuid_t userId, const unsigned char *auth_cipher) {
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
    while(!gmp_key_iter_end(iter)) {
        gmp_key_iter_get(iter, corrupted_key);
        // If encryption fails for some reason, break prematurely.
        if(!encryptMsg(corrupted_key, userId, sizeof(uuid_t), cipher, &outlen)) {
            found = -1;
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
    const size_t MISMATCHES = 3;
    size_t starting_perms_size = 8ULL;

    gmp_randstate_t randstate;

    uuid_t userId;
    char uuid_str[37];

    unsigned char *key;
    unsigned char *corrupted_key;
    unsigned char auth_cipher[EVP_MAX_BLOCK_LENGTH];

    mpz_t starting_perm, ending_perm;

    struct timespec startTime, endTime;

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

    mpz_inits(starting_perm, ending_perm, NULL);

    // Initialize values
    uuid_generate(userId);
    uuid_unparse(userId, uuid_str);
    printf("Using UUID: %s\n", uuid_str);

    // Set the gmp prng algorithm and set a seed based on the current time
    gmp_randinit_default(randstate);
    gmp_randseed_ui(randstate, (unsigned long)time(NULL));

    get_random_key(key, KEY_SIZE, randstate);
    get_random_corrupted_key(corrupted_key, key, MISMATCHES, KEY_SIZE, randstate);

    int outlen;
    if(!encryptMsg(corrupted_key, userId, sizeof(userId), auth_cipher, &outlen)) {
        // Cleanup
        mpz_clears(starting_perm, ending_perm, NULL);
        free(corrupted_key);
        free(key);

        return EXIT_FAILURE;
    }

    clock_gettime(CLOCK_MONOTONIC, &startTime);
    // Loop through every starting_perms, assuming that the array is already sorted.
    pid_t children[starting_perms_size];
    for(size_t i = 0; i < starting_perms_size; i++) {
        children[i] = fork();
        if(children[i] < 0) {
            perror("Fork error\n");

            return -1;
        }
        else if(children[i] == 0) {
            get_perm_pair(starting_perm, ending_perm, i, starting_perms_size, MISMATCHES, KEY_SIZE);
            int found = gmp_validator(starting_perm, ending_perm, key, KEY_SIZE, userId, auth_cipher);

            // Cleanup
            mpz_clears(starting_perm, ending_perm, NULL);
            free(corrupted_key);
            free(key);

            return found;
        }
    }

    int status;
    while(wait(&status) > 0 && !WEXITSTATUS(status));

    clock_gettime(CLOCK_MONOTONIC, &endTime);
    double duration = difftime(endTime.tv_sec, startTime.tv_sec) + ((endTime.tv_nsec - startTime.tv_nsec) / 1e9);

    if(WEXITSTATUS(status)) {
        for(size_t i = 0; i < 8; i++) {
            kill(children[i], SIGTERM);
            waitpid(children[i], NULL, 0);
        }
    }

    printf("Clock time: %f s\n", duration);
    printf("Found: %d", WEXITSTATUS(status));

    // Cleanup
    mpz_clears(starting_perm, ending_perm, NULL);
    free(corrupted_key);
    free(key);

    return 0;
}