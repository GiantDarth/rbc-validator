//
// Created by chaos on 2/23/2021.
//

#include "validator.h"

#ifdef USE_MPI
#include <mpi.h>
#endif

#include <string.h>

typedef struct validator_t {
    uint256_key_iter *iter;
    unsigned char *curr_seed;
#ifdef USE_MPI
    MPI_Request *requests;
    MPI_Status *statuses;
#endif
} validator_t;

validator_t* validator_create(const unsigned char *host_seed, const uint256_t *starting_perm,
                              const uint256_t *last_perm
#ifdef USE_MPI
                              , int nprocs
#endif
                              );
void validator_destroy(validator_t *v);

int aes256_crypto_func(unsigned char *curr_seed, void *args) {
    aes256_validator_t *v = (aes256_validator_t*)args;
    return aes256_ecb_encrypt(v->curr_cipher, curr_seed, v->msg, v->n);
}

int aes256_crypto_cmp(void *args) {
    aes256_validator_t *v = (aes256_validator_t*)args;
    return memcmp(v->curr_cipher, v->client_cipher, v->n);
}

int ec_crypto_func(unsigned char *curr_seed, void *args) {
    ec_validator_t *v = (ec_validator_t*)args;

    BN_bin2bn(curr_seed, SEED_SIZE, v->scalar);

    return !EC_POINT_mul(v->group, v->curr_point, v->scalar, NULL, NULL, v->ctx);
}

int ec_crypto_cmp(void *args) {
    ec_validator_t *v_args = (ec_validator_t*)args;

    return EC_POINT_cmp(v_args->group, v_args->curr_point, v_args->client_point, v_args->ctx);
}

validator_t* validator_create(const unsigned char *host_seed, const uint256_t *starting_perm,
                              const uint256_t *last_perm
#ifdef USE_MPI
                              , int nprocs
#endif
                              ) {
    validator_t *v = malloc(sizeof(*v));

    if(v == NULL) {
        return NULL;
    }

    if((v->iter = uint256_key_iter_create(host_seed, starting_perm, last_perm)) == NULL) {
        validator_destroy(v);

        return NULL;
    }

    if((v->curr_seed = malloc(SEED_SIZE * sizeof(*(v->curr_seed)))) == NULL) {
        validator_destroy(v);

        return NULL;
    }

#ifdef USE_MPI
    if((v->requests = malloc(nprocs * sizeof(*(v->requests)))) == NULL) {
        validator_destroy(v);

        return NULL;
    }

    if((v->statuses = malloc(nprocs * sizeof(*(v->statuses)))) == NULL) {
        validator_destroy(v);

        return NULL;
    }
#endif

    return v;
}

void validator_destroy(validator_t *v) {
    if(v == NULL) {
        return;
    }

#ifdef USE_MPI
    if(v->requests != NULL) {
        free(v->requests);
    }

    if(v->statuses != NULL) {
        free(v->statuses);
    }
#endif

    if(v->iter != NULL) {
        uint256_key_iter_destroy(v->iter);
    }

    free(v);
}


aes256_validator_t *aes256_validator_create(const unsigned char *msg, const unsigned char *client_cipher,
                                            size_t n) {
    aes256_validator_t *v = malloc(sizeof(*v));

    if(v == NULL) {
        aes256_validator_destroy(v);

        return NULL;
    }

    v->n = n;
    v->msg = msg;
    v->client_cipher = client_cipher;

    if(n % AES_BLOCK_SIZE != 0) {
        aes256_validator_destroy(v);

        return NULL;
    }

    if((v->curr_cipher = malloc(n * sizeof(*(v->curr_cipher)))) == NULL) {
        aes256_validator_destroy(v);

        return NULL;
    }

    return v;
}

void aes256_validator_destroy(aes256_validator_t *v) {
    if(v == NULL) {
        return;
    }

    if(v->curr_cipher != NULL) {
        free(v->curr_cipher);
    }

    free(v);
}

/// \param EC_GROUP The EC group to se
/// \param EC_POINT The client EC public key
ec_validator_t *ec_validator_create(const EC_GROUP *group, const EC_POINT *client_point) {
    ec_validator_t *v = malloc(sizeof(*v));

    if(v == NULL) {
        ec_validator_destroy(v);

        return NULL;
    }

    v->ctx_started = 0;
    v->group = group;
    v->client_point = client_point;

    if((v->client_point = EC_POINT_new(v->group)) == NULL) {
        ec_validator_destroy(v);

        return NULL;
    }

    if((v->curr_point = EC_POINT_new(v->group)) == NULL) {
        ec_validator_destroy(v);

        return NULL;
    }

    if((v->ctx = BN_CTX_new()) == NULL) {
        ec_validator_destroy(v);

        return NULL;
    }

    BN_CTX_start(v->ctx);
    v->ctx_started = 1;

    if((v->scalar = BN_CTX_get(v->ctx)) == NULL) {
        ec_validator_destroy(v);

        return NULL;
    }

    return v;
}

void ec_validator_destroy(ec_validator_t *v) {
    if(v == NULL) {
        return;
    }

    if(v->ctx != NULL) {
        if(v->ctx_started) {
            BN_CTX_end(v->ctx);
        }

        BN_CTX_free(v->ctx);
    }

    if(v->curr_point != NULL) {
        EC_POINT_free(v->curr_point);
    }

    if(v->client_point != NULL) {
        EC_POINT_free(v->curr_point);
    }

    free(v);
}

/// Given a starting permutation, iterate forward through every possible permutation until one that's
/// matching last_perm is found, or until a matching cipher is found.
/// \param client_key An allocated corrupted host_seed to fill if the corrupted host_seed was found.
/// Must be at least 32 bytes big.
/// \param host_seed The original AES host_seed.
/// \param client_cipher The client cipher (16 bytes) to test against.
/// \param userId A uuid_t that's used as the plaintext to encrypt.
/// \param starting_perm The permutation to start iterating from.
/// \param last_perm The final permutation to stop iterating at, inclusively.
/// \param signal A pointer to a shared value. Used to signal the function to prematurely leave.
/// \param all If benchmark mode is set to a non-zero value, then continue even if found.
/// \param validated_keys A counter to keep track of how many keys were traversed. If NULL, then this
/// is skipped.
/// \return Returns a 1 if found or a 0 if not. Returns a -1 if an error has occurred.
int find_matching_seed(unsigned char *client_seed, const unsigned char *host_seed,
                       const uint256_t *starting_perm, const uint256_t *last_perm,
                       int all, long long int *validated_keys,
#ifdef USE_MPI
                       int *signal, int verbose, int my_rank, int nprocs,
#else
                       const int* signal,
#endif
                       int (*crypto_func)(unsigned char*, void*), int (*crypto_cmp)(void*),
                       void *crypto_args) {
    // Declaration
    int status = 0;

#ifdef USE_MPI
    int probe_flag = 0;
    long long int iter_count = 0;
#endif

    validator_t *v = validator_create(host_seed, starting_perm, last_perm
#ifdef USE_MPI
                                      , nprocs
#endif
                                     );
    if(v == NULL) {
        return -1;
    }

    while(!uint256_key_iter_end(v->iter) && (all || !(*signal))) {
        if(validated_keys != NULL) {
            ++(*validated_keys);
        }
        uint256_key_iter_get(v->iter, v->curr_seed);

        // If crypto_func fails for some reason, break prematurely.
        if(crypto_func(v->curr_seed, crypto_args)) {
            status = -1;
            break;
        }

        // If the new crypto output is the same as the passed in client crypto output, set status to true
        // and break
        if(!crypto_cmp(crypto_args)) {
            status = 1;

#ifdef USE_MPI
            *signal = 1;

            if(verbose) {
                fprintf(stderr, "INFO: Found by rank: %d, alerting ranks ...\n", my_rank);
            }

            memcpy(client_seed, v->curr_seed, AES256_KEY_SIZE);

            if(!all) {
                // alert all ranks that the key was found, including yourself
                for (int i = 0; i < nprocs; i++) {
                    if(i != my_rank) {
                        MPI_Isend(signal, 1, MPI_INT, i, 0, MPI_COMM_WORLD,
                                  &(v->requests[i]));
                    }
                }

                for (int i = 0; i < nprocs; i++) {
                    if(i != my_rank) {
                        MPI_Wait(&(v->requests[i]), MPI_STATUS_IGNORE);
                    }
                }
            }
#else
            // Only have one thread copy the host_seed at a time
            // This might happen more than once if the # of threads exceeds the number of possible
            // keys
#pragma omp critical
            memcpy(client_seed, v->curr_seed, AES256_KEY_SIZE);
            break;
#endif
        }

#ifdef USE_MPI
        if (!all && !(*signal) && iter_count % 128 == 0) {
            MPI_Iprobe(MPI_ANY_SOURCE, 0, MPI_COMM_WORLD, &probe_flag, MPI_STATUS_IGNORE);

            if(probe_flag) {
                MPI_Recv(signal, 1, MPI_INT, MPI_ANY_SOURCE, 0, MPI_COMM_WORLD,
                        MPI_STATUS_IGNORE);
            }
        }
#endif

        uint256_key_iter_next(v->iter);
    }

    validator_destroy(v);

    return status;
}
