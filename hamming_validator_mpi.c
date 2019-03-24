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
#include <pthread.h>

#include "gmp_key_iter.h"
#include "util.h"

#define ERROR_CODE_FOUND 0
#define ERROR_CODE_NOT_FOUND 1
#define ERROR_CODE_FAILURE 2

MPI_Status status;
MPI_Request request;

int found = 0;
int firstfound = 0;
int flags[2] = {0,-1};
int my_rank, nprocs, mode, base_cycles;

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
                     size_t key_size, uuid_t userId, const unsigned char *auth_cipher, int cycles, int my_rank, int nprocs) {

    int sum = 0;
    // Declaration
    unsigned char *corrupted_key;
    unsigned char cipher[EVP_MAX_BLOCK_LENGTH];
    int outlen = 0;
    //found = 0;

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
            flags[0] = 1;
            // pthread con signal (signal)
        }


        // all ranks are hitting this, need to send two ints, one int is flag
        // other int is the rank that found it, then do somethin like
        // if (found ==1 && my_rank = ints[1])
        if (flags[0] == 1 && flags[1] == -1){
          flags[0] = 1;
          flags[1] = my_rank;
          printf("Found by rank: %d, alerting ranks ...\n",my_rank);

          for (int i = 0; i < nprocs; i++) {
            MPI_Isend(&flags,2,MPI_INT,i,0,MPI_COMM_WORLD,&request);
            MPI_Wait(&request,MPI_STATUS_IGNORE);
          }
          //printf("we done, break!\n");

          break;
        }

        // for all ranks that didn't find it first
        if (flags[0] == 1) {
          break;
        }
        // remove this comment block to enable early exit on valid key found
        // count is a tuning knob for how often the MPI collective should check
        // if the right key has been found.
        /*if(count == cycles) {


            MPI_Allreduce(&found, &sum, 1, MPI_INT, MPI_SUM, MPI_COMM_WORLD);
            //MPI_Iallreduce(&found, &sum, 1, MPI_INT, MPI_SUM, MPI_COMM_WORLD, &request);

            if(sum == 1) {
                if (my_rank == 0) {
                  printf("Found: 1\n");
                }
                  break;
                //return found;
            }

            count = 0;
        }*/

        gmp_key_iter_next(iter);
    }

    // Cleanup
    gmp_key_iter_destroy(iter);
    free(corrupted_key);

    return found;
}

// this code derived from stack exchange
int choose(int n, int k) {
    if (k == 0) {
      return 1;
    }else{
      return (n * choose(n - 1, k - 1)) / k;
    }
}

// get_numcycles
// we will be able to run in multiple modes:
// - cycles fixed (mode 0)
// - cycles increasing with cores (mode 1)
// - cycles decreasing with cores (mode 2)
// - cycles proportional (mode 3)

// as mismatches go up, combinations will go up, how do we increase the cycles per core too?
// inherently with combinations going up, processors will have more combinations to work on
int get_numcycles(int key_size, int mismatches, int nprocs, int mode, int base_cycles) {
  // fixed default size
  int num_cycles = base_cycles;
  int combinations = choose(key_size*8,mismatches);

  if (mode == 0){
    return num_cycles;
  } else if (mode == 1) {
    return num_cycles*(nprocs*(.015));
  }else if (mode == 2) {
    return num_cycles*200*(1/nprocs);
  } else if (mode == 3) {
    num_cycles = combinations/(key_size*nprocs*mismatches);
    return num_cycles;
  }


  return num_cycles;
}

// how to handle the issue with the request and status
void *comm (void *arg) {
  //int found = 0;

  MPI_Recv(&flags,2,MPI_INT,MPI_ANY_SOURCE,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
  MPI_Wait(&request,MPI_STATUS_IGNORE);

  printf("Rank: %d sees that rank: %d found it!\n", my_rank, flags[1]);
  // only way we get here is if it was found, no reason to check
  //  return 0;
  pthread_exit(0);
}
/// MPI implementation
/// \return Returns a 0 on successfully finding a match, a 1 when unable to find a match,
/// and a 2 when a general error has occurred.
int main(int argc, char **argv) {
    //int found = 0;
    pthread_t com_thread;

    MPI_Init(&argc, &argv);
    MPI_Comm_rank(MPI_COMM_WORLD, &my_rank);
    MPI_Comm_size(MPI_COMM_WORLD, &nprocs);
    //MPI_Status status;
    request = MPI_REQUEST_NULL;

    if (pthread_create( &com_thread, NULL, comm, 0)) {
      fprintf(stderr,"Error while creating comm thread\n");
      exit(1);
    }


    const size_t KEY_SIZE = 32;
    const size_t MISMATCHES = atoi(argv[1]);
    mode = atoi(argv[2]);
    base_cycles = atoi(argv[3]);

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

        MPI_Abort(MPI_COMM_WORLD, ERROR_CODE_FAILURE);
    }

    if((corrupted_key = malloc(sizeof(*corrupted_key) * KEY_SIZE)) == NULL) {
        perror("Error");
        free(key);

        MPI_Abort(MPI_COMM_WORLD, ERROR_CODE_FAILURE);
    }

    mpz_inits(starting_perm, ending_perm, NULL);

    if(my_rank == 0) {
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

        int outlen;
        if(!encryptMsg(corrupted_key, userId, sizeof(userId), auth_cipher, &outlen)) {
            // Cleanup
            mpz_clears(starting_perm, ending_perm, NULL);
            free(corrupted_key);
            free(key);

            MPI_Abort(MPI_COMM_WORLD, ERROR_CODE_FAILURE);
        }
    } // end rank 0

    // all ranks

    MPI_Bcast(userId, sizeof(userId), MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);
    MPI_Bcast(auth_cipher, EVP_MAX_BLOCK_LENGTH, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);
    MPI_Bcast(key, KEY_SIZE, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);

    //printf("rank: %d received this for key: ", my_rank);
    //print_hex(key, KEY_SIZE);
    //printf("\n");

    // Initialize time for root rank
    if(my_rank == 0) {
        clock_gettime(CLOCK_MONOTONIC, &startTime);
    }


    int cycles = get_numcycles(KEY_SIZE, MISMATCHES, nprocs, mode, base_cycles);


    get_perm_pair(starting_perm, ending_perm, (size_t)my_rank, (size_t)nprocs, MISMATCHES, KEY_SIZE);
    int subfound = gmp_validator(starting_perm, ending_perm, key, KEY_SIZE, userId, auth_cipher, cycles, my_rank, nprocs);



    if(subfound < 0) {
        // Cleanup
        mpz_clears(starting_perm, ending_perm, NULL);
        free(corrupted_key);
        free(key);

        MPI_Abort(MPI_COMM_WORLD, ERROR_CODE_FAILURE);
    }

    // Reduce all the "found" answers to a single found statement.
    // Also works as a natural barrier to make sure all processes are done validating before ending time.
    //int found = 0;
    //MPI_Reduce(&subfound, &found, 1, MPI_INT, MPI_SUM, 0, MPI_COMM_WORLD);

    if(my_rank == 0) {
        clock_gettime(CLOCK_MONOTONIC, &endTime);
        double duration = difftime(endTime.tv_sec, startTime.tv_sec) + ((endTime.tv_nsec - startTime.tv_nsec) / 1e9);

        printf("Num cycles: %d\n", cycles);
        printf("Clock time: %f s\n", duration);
        //if (subfound == 1) {
        //  printf("Found: %d\n", subfound);
        //}
    }

    // Cleanup
    mpz_clears(starting_perm, ending_perm, NULL);
    free(corrupted_key);
    free(key);

    printf("Rank: %d is Thread join ...\n", my_rank);
    pthread_join(com_thread, NULL);

    //MPI_Barrier(MPI_COMM_WORLD);
    printf("Rank: %d is Finalize ...\n", my_rank);
    MPI_Finalize();

    exit(0);

    /*if(my_rank == 0) {
        return found ? ERROR_CODE_FOUND : ERROR_CODE_NOT_FOUND;
    }
    else {
        return ERROR_CODE_FOUND;
    }
    */
}
