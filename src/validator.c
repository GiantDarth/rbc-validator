//
// Created by chaos on 2/23/2021.
//

#include "validator.h"

#ifdef USE_MPI
#include <mpi.h>
#endif

#include <string.h>

#include "seed_iter.h"
#include "crypto/cipher.h"
#include "crypto/ec.h"

int aes256_crypto_func(const unsigned char *curr_seed, void *args) {
    cipher_validator_t *v = (cipher_validator_t*)args;

    if(v == NULL) {
        return -1;
    }

    return aes256_ecb_encrypt(v->curr_cipher, curr_seed, v->msg, v->msg_size);
}

int aes256_crypto_cmp(void *args) {
    cipher_validator_t *v = (cipher_validator_t*)args;

    if(v == NULL || v->curr_cipher == NULL || v->client_cipher == NULL) {
        return -1;
    }

    return memcmp(v->curr_cipher, v->client_cipher, v->msg_size) != 0;
}

int cipher_crypto_func(const unsigned char *curr_seed, void *args) {
    cipher_validator_t *v = (cipher_validator_t*)args;

    if(v == NULL || v->ctx == NULL) {
        return 1;
    }

    if(evp_encrypt(v->curr_cipher, v->ctx, v->evp_cipher, curr_seed, v->msg, v->msg_size, v->iv)) {
        return 1;
    }

    // By setting the EVP structure to NULL, we avoid reallocation later
    if(v->evp_cipher != NULL) {
        v->evp_cipher = NULL;
        v->iv = NULL;
    }

    return 0;
}

int cipher_crypto_cmp(void *args) {
    cipher_validator_t *v = (cipher_validator_t*)args;

    if(v == NULL || v->curr_cipher == NULL || v->client_cipher == NULL) {
        return -1;
    }

    return memcmp(v->curr_cipher, v->client_cipher, v->msg_size) != 0;
}

int ec_crypto_func(const unsigned char *curr_seed, void *args) {
    ec_validator_t *v = (ec_validator_t*)args;

    if(v == NULL) {
        return -1;
    }

    return get_ec_public_key(v->curr_point, v->ctx, v->group, curr_seed, SEED_SIZE);
}

int ec_crypto_cmp(void *args) {
    ec_validator_t *v = (ec_validator_t*)args;

    if(v == NULL) {
        return -1;
    }

    return EC_POINT_cmp(v->group, v->curr_point, v->client_point, v->ctx);
}

cipher_validator_t *cipher_validator_create(const EVP_CIPHER *evp_cipher,
                                            const unsigned char *client_cipher, const unsigned char *msg,
                                            size_t msg_size, const unsigned char *iv) {
    cipher_validator_t *v = malloc(sizeof(*v));

    if(v == NULL) {
        return NULL;
    }

    v->evp_cipher = evp_cipher;
    v->msg_size = msg_size;
    v->msg = msg;
    v->client_cipher = client_cipher;
    // IV is optional as NULL depending on the cipher chosen
    v->iv = iv;

    v->curr_cipher = malloc(msg_size * sizeof(*(v->curr_cipher)));
    v->ctx = EVP_CIPHER_CTX_new();

    if(v->evp_cipher == NULL || v->msg == NULL || v->client_cipher == NULL || v->curr_cipher == NULL
            || v->ctx == NULL) {
        cipher_validator_destroy(v);

        return NULL;
    }

    if(v->msg_size % EVP_CIPHER_block_size(v->evp_cipher) != 0) {
        cipher_validator_destroy(v);

        return NULL;
    }

    if((v->iv == NULL && EVP_CIPHER_iv_length(v->evp_cipher) != 0)
            || (v->iv != NULL && EVP_CIPHER_iv_length(v->evp_cipher) == 0)) {
        cipher_validator_destroy(v);

        return NULL;
    }

    return v;
}

void cipher_validator_destroy(cipher_validator_t *v) {
    if(v == NULL) {
        return;
    }

    if(v->ctx != NULL) {
        EVP_CIPHER_CTX_free(v->ctx);
    }

    if(v->curr_cipher != NULL) {
        free(v->curr_cipher);
    }

    free(v);
}

ec_validator_t *ec_validator_create(const EC_GROUP *group, const EC_POINT *client_point) {
    ec_validator_t *v = malloc(sizeof(*v));

    if(v == NULL || group == NULL || client_point == NULL) {
        ec_validator_destroy(v);

        return NULL;
    }

    v->group = group;
    v->client_point = client_point;

    v->curr_point = EC_POINT_new(v->group);
    v->ctx = BN_CTX_secure_new();

    if(v->curr_point == NULL || v->ctx == NULL) {
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
    int status = 0, cmp_status = 1;
    seed_iter iter;
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

    seed_iter_init(&iter, host_seed, SEED_SIZE, first_perm, last_perm);

    while(!seed_iter_end(&iter) && (all || !(*signal))) {
        if(validated_keys != NULL) {
            ++(*validated_keys);
        }
        curr_seed = seed_iter_get(&iter);

        // If crypto_func fails for some reason, break prematurely.
        if(crypto_func != NULL && crypto_func(curr_seed, crypto_args)) {
            status = -1;
            break;
        }

        // If crypto_cmp fails for some reason, break prematurely.
        if(crypto_cmp != NULL && (cmp_status = crypto_cmp(crypto_args)) < 0) {
            status = -1;
            break;
        }

        // If the new crypto output is the same as the passed in client crypto output, set status to true
        // and break
        if(cmp_status == 0) {
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

        seed_iter_next(&iter);
    }

#ifdef USE_MPI
    free(requests);
    free(statuses);
#endif

    return status;
}
