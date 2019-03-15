//
// Created by cp723 on 2/7/2019.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

#include <uuid/uuid.h>
#include <gmp.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>

#include "uint256_key_iter.h"
#include "aes256-ni.h"
#include "util.h"

#define ERROR_CODE_FOUND 0
#define ERROR_CODE_NOT_FOUND 1
#define ERROR_CODE_FAILURE 2

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
int gmp_validator(const uint256_t *starting_perm, const uint256_t *last_perm, const unsigned char *key,
        size_t key_size, uuid_t userId, const unsigned char *auth_cipher) {
    // Declaration
    unsigned char *corrupted_key;
    unsigned char cipher[sizeof(uuid_t)];
    int found = 0;

    uint256_key_iter *iter;
    aes256_enc_key_scheduler *key_scheduler;

    // Memory allocation
    if((corrupted_key = malloc(sizeof(*corrupted_key) * key_size)) == NULL) {
        perror("Error");

        return -1;
    }

    if((key_scheduler = aes256_enc_key_scheduler_create()) == NULL) {
        perror("Error");
        free(corrupted_key);

        return -1;
    }

    // Allocation and initialization
    if((iter = uint256_key_iter_create(key, starting_perm, last_perm)) == NULL) {
        perror("Error");
        aes256_enc_key_scheduler_destroy(key_scheduler);
        free(corrupted_key);

        return -1;
    }

    // While we haven't reached the end of iteration
    while(!uint256_key_iter_end(iter)) {
        uint256_key_iter_get(iter, corrupted_key);
        aes256_enc_key_scheduler_update(key_scheduler, key);

        // If encryption fails for some reason, break prematurely.
        if(aes256_ecb_encrypt(cipher, key_scheduler, userId, sizeof(uuid_t))) {
            found = -1;
            break;
        }

        // If the new cipher is the same as the passed in auth_cipher, set found to true and break
        if(memcmp(cipher, auth_cipher, sizeof(uuid_t)) == 0) {
            found = 1;
            break;
        }

        uint256_key_iter_next(iter);
    }

    // Cleanup
    uint256_key_iter_destroy(iter);
    aes256_enc_key_scheduler_destroy(key_scheduler);
    free(corrupted_key);

    return found;
}

/// Fork implementation
/// \return Returns a 0 on successfully finding a match, a 1 when unable to find a match,
/// and a 2 when a general error has occurred.
int main() {
    const size_t KEY_SIZE = 32;
    const size_t MISMATCHES = 3;
    size_t starting_perms_size = 8ULL;

    gmp_randstate_t randstate;

    uuid_t userId;
    char uuid_str[37];

    unsigned char *key;
    unsigned char *corrupted_key;
    unsigned char auth_cipher[sizeof(uuid_t)];

    aes256_enc_key_scheduler *key_scheduler;

    uint256_t starting_perm, ending_perm;

    struct timespec startTime, endTime;

    // Memory allocation
    if((key = malloc(sizeof(*key) * KEY_SIZE)) == NULL) {
        perror("Error");

        return ERROR_CODE_FAILURE;
    }

    if((corrupted_key = malloc(sizeof(*corrupted_key) * KEY_SIZE)) == NULL) {
        perror("Error");
        free(key);

        return ERROR_CODE_FAILURE;
    }

    if((key_scheduler = aes256_enc_key_scheduler_create()) == NULL) {
        free(corrupted_key);
        free(key);

        return ERROR_CODE_FAILURE;
    }

    // Initialize values
    uuid_generate(userId);

    // Convert the uuid to a string for printing
    uuid_unparse(userId, uuid_str);
    printf("Using UUID: %s\n", uuid_str);

    // Set the gmp prng algorithm and set a seed based on the current time
    gmp_randinit_default(randstate);
    gmp_randseed_ui(randstate, (unsigned long)time(NULL));

    get_random_key(key, KEY_SIZE, randstate);
    get_random_corrupted_key(corrupted_key, key, MISMATCHES, KEY_SIZE, randstate);

    if(aes256_ecb_encrypt(auth_cipher, key_scheduler, userId, sizeof(uuid_t))) {
        // Cleanup
        aes256_enc_key_scheduler_destroy(key_scheduler);
        free(corrupted_key);
        free(key);

        return ERROR_CODE_FAILURE;
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
            uint256_get_perm_pair(&starting_perm, &ending_perm, i, starting_perms_size, MISMATCHES, KEY_SIZE);
            int found = gmp_validator(&starting_perm, &ending_perm, key, KEY_SIZE, userId, auth_cipher);

            // Cleanup
            aes256_enc_key_scheduler_destroy(key_scheduler);
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
    printf("Found: %d\n", WEXITSTATUS(status));

    // Cleanup
    aes256_enc_key_scheduler_destroy(key_scheduler);
    free(corrupted_key);
    free(key);

    return WEXITSTATUS(status) ? ERROR_CODE_FOUND : ERROR_CODE_NOT_FOUND;
}