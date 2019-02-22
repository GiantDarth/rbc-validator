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
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>

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

void get_perm_pair(mpz_t starting_perm, mpz_t ending_perm, size_t pair_index, size_t pair_count,
        size_t mismatches, size_t key_size) {
    mpz_t total_perms, starting_ordinal, ending_ordinal;
    mpz_inits(total_perms, starting_ordinal, ending_ordinal, NULL);

    mpz_bin_uiui(total_perms, key_size * 8, mismatches);

    if(pair_index == 0) {
        gmp_assign_first_permutation(starting_perm, mismatches);
    }
    else {
        mpz_tdiv_q_ui(starting_ordinal, total_perms, pair_count);
        mpz_mul_ui(starting_ordinal, starting_ordinal, pair_index);

        decode_ordinal(starting_perm, starting_ordinal, mismatches, key_size);
    }

    if(pair_index == pair_count - 1) {
        gmp_assign_last_permutation(ending_perm, mismatches, key_size);
    }
    else {
        mpz_tdiv_q_ui(ending_ordinal, total_perms, pair_count);
        mpz_mul_ui(ending_ordinal, ending_ordinal, pair_index + 1);

        decode_ordinal(ending_perm, ending_ordinal, mismatches, key_size);
    }

    mpz_clears(total_perms, starting_ordinal, ending_ordinal, NULL);
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
    const size_t MISMATCHES = 4;
    size_t starting_perms_size = 8ULL;

    gmp_randstate_t randstate;

    uuid_t userId;
    char uuid_str[37];

    unsigned char *key;
    unsigned char *corrupted_key;
    unsigned char auth_cipher[EVP_MAX_BLOCK_LENGTH];

    mpz_t starting_perm, ending_perm;

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
    get_random_corrupted_key(key, corrupted_key, MISMATCHES, KEY_SIZE, randstate);

    int outlen;
    if(!encryptMsg(corrupted_key, userId, sizeof(userId), auth_cipher, &outlen)) {
        // Cleanup
        mpz_clears(starting_perm, ending_perm, NULL);
        free(corrupted_key);
        free(key);

        return EXIT_FAILURE;
    }

    double startTime = omp_get_wtime();
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

            printf("%zu, %d\n", i, found);

            // Cleanup
            mpz_clears(starting_perm, ending_perm, NULL);
            free(corrupted_key);
            free(key);

            return found;
        }
    }

    int status;
    while(wait(&status) > 0 && !WEXITSTATUS(status));

    if(WEXITSTATUS(status)) {
        for(size_t i = 0; i < 8; i++) {
            kill(children[i], SIGTERM);
            waitpid(children[i], NULL, 0);
        }
    }

    double duration = omp_get_wtime() - startTime;

    printf("Clock time: %f s\n", duration);

    printf("Found: %d", WEXITSTATUS(status));

    // Cleanup
    mpz_clears(starting_perm, ending_perm, NULL);
    free(corrupted_key);
    free(key);

    return 0;
}