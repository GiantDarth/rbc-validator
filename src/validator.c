//
// Created by chaos on 2/23/2021.
//

#include "validator.h"

#ifdef USE_MPI
#include <mpi.h>
#endif

#include <string.h>

#include "gmp_seed_iter.h"

int aes256_crypto_func(const unsigned char *curr_seed, void *args) {
    aes256_validator_t *v = (aes256_validator_t*)args;
    return aes256_ecb_encrypt(v->curr_cipher, curr_seed, v->msg, v->n);
}

int aes256_crypto_cmp(void *args) {
    aes256_validator_t *v = (aes256_validator_t*)args;
    return memcmp(v->curr_cipher, v->client_cipher, v->n);
}

int ec_crypto_func(const unsigned char *curr_seed, void *args) {
    ec_validator_t *v = (ec_validator_t*)args;

    BN_bin2bn(curr_seed, SEED_SIZE, v->scalar);

    return !EC_POINT_mul(v->group, v->curr_point, v->scalar, NULL, NULL, v->ctx);
}

int ec_crypto_cmp(void *args) {
    ec_validator_t *v_args = (ec_validator_t*)args;

    return EC_POINT_cmp(v_args->group, v_args->curr_point, v_args->client_point, v_args->ctx);
}

aes256_validator_t *aes256_validator_create(const unsigned char *msg, const unsigned char *client_cipher,
                                            size_t n) {
    aes256_validator_t *v = malloc(sizeof(*v));

    if(v == NULL) {
        aes256_validator_destroy(v);

        return NULL;
    }

    if(msg == NULL || client_cipher == NULL) {
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

    if(group == NULL || client_point == NULL) {
        ec_validator_destroy(v);

        return NULL;
    }

    v->ctx_started = 0;
    v->group = group;
    v->client_point = client_point;

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

    free(v);
}

/// Given a starting permutation, iterate forward through every possible permutation until one that's
/// matching last_perm is found, or until a matching cipher is found.
/// \param client_key An allocated corrupted host_seed to fill if the corrupted host_seed was found.
/// Must be at least 32 bytes big.
/// \param host_seed The original AES host_seed.
/// \param client_cipher The client cipher (16 bytes) to test against.
/// \param userId A uuid_t that's used as the plaintext to encrypt.
/// \param first_perm The permutation to start iterating from.
/// \param last_perm The final permutation to stop iterating at, inclusively.
/// \param signal A pointer to a shared value. Used to signal the function to prematurely leave.
/// \param all If benchmark mode is set to a non-zero value, then continue even if found.
/// \param validated_keys A counter to keep track of how many keys were traversed. If NULL, then this
/// is skipped.
/// \return Returns a 1 if found or a 0 if not. Returns a -1 if an error has occurred.
int find_matching_seed(unsigned char *client_seed, const unsigned char *host_seed,
                       const mpz_t first_perm, const mpz_t last_perm,
                       int all, long long int *validated_keys,
#ifdef USE_MPI
                       int *signal, int verbose, int my_rank, int nprocs,
#else
                       const int* signal,
#endif
                       int (*crypto_func)(const unsigned char*, void*), int (*crypto_cmp)(void*),
                       void *crypto_args) {
    // Declaration
    int status = 0;
    gmp_seed_iter iter;
    const unsigned char *curr_seed;
#ifdef USE_MPI
    int probe_flag = 0;
    long long int iter_count = 0;

    MPI_Request *requests;
    MPI_Status *statuses;

    if((requests = malloc(nprocs * sizeof(*(requests)))) == NULL) {
        return -1;
    }

    if((statuses = malloc(nprocs * sizeof(*(statuses)))) == NULL) {
        free(requests);

        return -1;
    }
#endif

    gmp_seed_iter_init(&iter, host_seed, SEED_SIZE, first_perm, last_perm);

    while(!gmp_seed_iter_end(&iter) && (all || !(*signal))) {
        if(validated_keys != NULL) {
            ++(*validated_keys);
        }
        curr_seed = gmp_seed_iter_get(&iter);

        // If crypto_func fails for some reason, break prematurely.
        if(crypto_func(curr_seed, crypto_args)) {
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

            memcpy(client_seed, curr_seed, SEED_SIZE);

            if(!all) {
                // alert all ranks that the key was found, including yourself
                for (int i = 0; i < nprocs; i++) {
                    if(i != my_rank) {
                        MPI_Isend(signal, 1, MPI_INT, i, 0, MPI_COMM_WORLD, &(requests[i]));
                    }
                }

                for (int i = 0; i < nprocs; i++) {
                    if(i != my_rank) {
                        MPI_Wait(&(requests[i]), MPI_STATUS_IGNORE);
                    }
                }
            }
#else
            // Only have one thread copy the host_seed at a time
            // This might happen more than once if the # of threads exceeds the number of possible
            // keys
#pragma omp critical
            memcpy(client_seed, curr_seed, SEED_SIZE);
            break;
#endif
        }

#ifdef USE_MPI
        if (!all && !(*signal) && iter_count % 128 == 0) {
            MPI_Iprobe(MPI_ANY_SOURCE, 0, MPI_COMM_WORLD, &probe_flag, MPI_STATUS_IGNORE);

            if(probe_flag) {
                MPI_Recv(signal, 1, MPI_INT, MPI_ANY_SOURCE, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
            }
        }
#endif

        gmp_seed_iter_next(&iter);
    }

#ifdef USE_MPI
    free(requests);
    free(statuses);
#endif

    return status;
}
