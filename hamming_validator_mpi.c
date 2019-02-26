//
// Created by cp723 on 2/7/2019.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <mpi.h>

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

    int sum = 0;
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

    int count = 0;
    // While we haven't reached the end of iteration
    while(!gmp_key_iter_end(iter)) {
        count++;
        gmp_key_iter_get(iter, corrupted_key);
        // If encryption fails for some reason, break prematurely.
        if(!encryptMsg(corrupted_key, userId, sizeof(uuid_t), cipher, &outlen)) {
            // Cleanup
            gmp_key_iter_destroy(iter);
            free(corrupted_key);
            return -1;
        }
        // If the new cipher is the same as the passed in auth_cipher, set found to true and break
        if(memcmp(cipher, auth_cipher, (size_t)outlen) == 0) {
            found = 1;
        }

        // remove this comment block to enable early exit on valid key found
        // count is a tuning knob for how often the MPI collective should check
        // if the right key has been found.
        if(count == 10000) {
            MPI_Allreduce(&found, &sum, 1, MPI_INT, MPI_SUM, MPI_COMM_WORLD);

            if(sum == 1) {
                MPI_Finalize();
                exit(0);
            }

            // not found yet, we'll check back after count is reached again
            count = 0;
        }
        gmp_key_iter_next(iter);
    }

    // Cleanup
    gmp_key_iter_destroy(iter);
    free(corrupted_key);

    return found;
}

int main(int argc, char **argv) {
    int my_rank, nprocs;

    MPI_Init(&argc,&argv);
    MPI_Comm_rank(MPI_COMM_WORLD,&my_rank);
    MPI_Comm_size(MPI_COMM_WORLD,&nprocs);
    MPI_Status status;
    MPI_Request request=MPI_REQUEST_NULL;

    const size_t KEY_SIZE = 32;
    const size_t MISMATCHES = 3;

    gmp_randstate_t randstate;

    uuid_t userId;
    char uuid_str[37];

    unsigned char *key;
    unsigned char *corrupted_key;
    unsigned char auth_cipher[EVP_MAX_BLOCK_LENGTH];

    mpz_t starting_perm, ending_perm;

    struct timespec startTime, endTime;

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

    if (my_rank == 0) {
        // Memory allocation

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


    } // end rank 0

    //clock_gettime(CLOCK_MONOTONIC, &startTime);

    // all ranks

    MPI_Bcast(userId, sizeof(userId), MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);
    MPI_Bcast(auth_cipher, EVP_MAX_BLOCK_LENGTH, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);
    MPI_Bcast(key, KEY_SIZE, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);

    //printf("rank: %d received this for key: ", my_rank);
    //print_hex(key, KEY_SIZE);
    //printf("\n");

    get_perm_pair(starting_perm, ending_perm, (size_t)my_rank, (size_t)nprocs, MISMATCHES, KEY_SIZE);
    gmp_validator(starting_perm, ending_perm, key, KEY_SIZE, userId, auth_cipher);

    if (my_rank == 0) {
      printf("Checked all combinations!\n");
    }

    mpz_clears(starting_perm, ending_perm, NULL);
    free(corrupted_key);
    free(key);

    MPI_Finalize();
    return 0;

}
