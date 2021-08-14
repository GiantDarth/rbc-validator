//
// Created by chaos on 2/23/2021.
//

#include "validator.h"

#ifdef USE_MPI
#include <mpi.h>
#endif

#include <string.h>

#include "crypto/cipher.h"
#include "crypto/ec.h"
#include "crypto/hash.h"
#include "seed_iter.h"

int CryptoFunc_aes256(const unsigned char* curr_seed, void* args) {
    CipherValidator* v = (CipherValidator*)args;

    if (v == NULL) {
        return -1;
    }

    return aes256EcbEncrypt(v->curr_cipher, curr_seed, v->msg, v->msg_size);
}

int CryptoCmp_aes256(void* args) {
    CipherValidator* v = (CipherValidator*)args;

    if (v == NULL || v->curr_cipher == NULL || v->client_cipher == NULL) {
        return -1;
    }

    return memcmp(v->curr_cipher, v->client_cipher, v->msg_size) != 0;
}

int CryptoFunc_cipher(const unsigned char* curr_seed, void* args) {
    CipherValidator* v = (CipherValidator*)args;

    if (v == NULL || v->ctx == NULL) {
        return 1;
    }

    if (evpEncrypt(v->curr_cipher, v->ctx, v->evp_cipher, curr_seed, v->msg, v->msg_size, v->iv)) {
        return 1;
    }

    // By setting the EVP structure to NULL, we avoid reallocation later
    if (v->evp_cipher != NULL) {
        v->evp_cipher = NULL;
        v->iv = NULL;
    }

    return 0;
}

int CryptoCmp_cipher(void* args) {
    CipherValidator* v = (CipherValidator*)args;

    if (v == NULL || v->curr_cipher == NULL || v->client_cipher == NULL) {
        return -1;
    }

    return memcmp(v->curr_cipher, v->client_cipher, v->msg_size) != 0;
}

int CryptoFunc_ec(const unsigned char* curr_seed, void* args) {
    EcValidator* v = (EcValidator*)args;

    if (v == NULL) {
        return -1;
    }

    return getEcPublicKey(v->curr_point, v->ctx, v->group, curr_seed, SEED_SIZE);
}

int CryptoCmp_ec(void* args) {
    EcValidator* v = (EcValidator*)args;

    if (v == NULL) {
        return -1;
    }

    return EC_POINT_cmp(v->group, v->curr_point, v->client_point, v->ctx);
}

int CryptoFunc_hash(const unsigned char* curr_seed, void* args) {
    HashValidator* v = (HashValidator*)args;

    if (v == NULL) {
        return -1;
    }

    switch (v->nid) {
#ifndef ALWAYS_EVP_HASH
        case NID_md5:
            return md5Hash(v->curr_digest, curr_seed, SEED_SIZE, v->salt, v->salt_size);
        case NID_sha1:
            return sha1Hash(v->curr_digest, curr_seed, SEED_SIZE, v->salt, v->salt_size);
        case NID_sha224:
            return sha224Hash(v->curr_digest, curr_seed, SEED_SIZE, v->salt, v->salt_size);
        case NID_sha256:
            return sha256Hash(v->curr_digest, curr_seed, SEED_SIZE, v->salt, v->salt_size);
        case NID_sha384:
            return sha384Hash(v->curr_digest, curr_seed, SEED_SIZE, v->salt, v->salt_size);
        case NID_sha512:
            return sha512Hash(v->curr_digest, curr_seed, SEED_SIZE, v->salt, v->salt_size);
#endif
#ifndef ALWAYS_EVP_SHA3
        case NID_sha3_224:
            return sha3_224_hash(v->curr_digest, curr_seed, SEED_SIZE, v->salt, v->salt_size);
        case NID_sha3_256:
            return sha3_256_hash(v->curr_digest, curr_seed, SEED_SIZE, v->salt, v->salt_size);
        case NID_sha3_384:
            return sha3_384_hash(v->curr_digest, curr_seed, SEED_SIZE, v->salt, v->salt_size);
        case NID_sha3_512:
            return sha3_512_hash(v->curr_digest, curr_seed, SEED_SIZE, v->salt, v->salt_size);
        case NID_shake128:
            return shake128_hash(v->curr_digest, v->digest_size, curr_seed, SEED_SIZE, v->salt,
                                 v->salt_size);
        case NID_shake256:
            return shake256_hash(v->curr_digest, v->digest_size, curr_seed, SEED_SIZE, v->salt,
                                 v->salt_size);
#endif
        case NID_kang12:
            return kang12Hash(v->curr_digest, v->digest_size, curr_seed, SEED_SIZE, v->salt,
                              v->salt_size);
        default:
            return evpHash(v->curr_digest, v->is_xof ? &(v->digest_size) : NULL, v->ctx, v->md,
                           curr_seed, SEED_SIZE, v->salt, v->salt_size);
    }
}

int CryptoCmp_hash(void* args) {
    HashValidator* v = (HashValidator*)args;

    if (v == NULL) {
        return -1;
    }

    return memcmp(v->curr_digest, v->client_digest, v->digest_size) != 0;
}

int CryptoFunc_kang12(const unsigned char* curr_seed, void* args) {
    Kang12Validator* v = (Kang12Validator*)args;

    if (v == NULL) {
        return 1;
    }

    return kang12Hash(v->curr_digest, v->digest_size, curr_seed, SEED_SIZE, v->salt, v->salt_size);
}

int CryptoCmp_kang12(void* args) {
    Kang12Validator* v = (Kang12Validator*)args;

    if (v == NULL) {
        return -1;
    }

    return memcmp(v->curr_digest, v->client_digest, v->digest_size) != 0;
}

CipherValidator* CipherValidator_create(const EVP_CIPHER* evp_cipher,
                                        const unsigned char* client_cipher,
                                        const unsigned char* msg, size_t msg_size,
                                        const unsigned char* iv) {
    CipherValidator* v = malloc(sizeof(*v));

    if (v == NULL) {
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

    if (v->evp_cipher == NULL || v->msg == NULL || v->client_cipher == NULL ||
        v->curr_cipher == NULL || v->ctx == NULL) {
        CipherValidator_destroy(v);

        return NULL;
    }

    if (v->msg_size % EVP_CIPHER_block_size(v->evp_cipher) != 0) {
        CipherValidator_destroy(v);

        return NULL;
    }

    if ((v->iv == NULL && EVP_CIPHER_iv_length(v->evp_cipher) != 0) ||
        (v->iv != NULL && EVP_CIPHER_iv_length(v->evp_cipher) == 0)) {
        CipherValidator_destroy(v);

        return NULL;
    }

    return v;
}

void CipherValidator_destroy(CipherValidator* v) {
    if (v == NULL) {
        return;
    }

    if (v->ctx != NULL) {
        EVP_CIPHER_CTX_free(v->ctx);
    }

    if (v->curr_cipher != NULL) {
        free(v->curr_cipher);
    }

    free(v);
}

EcValidator* EcValidator_create(const EC_GROUP* group, const EC_POINT* client_point) {
    EcValidator* v = malloc(sizeof(*v));

    if (v == NULL || group == NULL || client_point == NULL) {
        EcValidator_destroy(v);

        return NULL;
    }

    v->group = group;
    v->client_point = client_point;

    v->curr_point = EC_POINT_new(v->group);
    v->ctx = BN_CTX_secure_new();

    if (v->curr_point == NULL || v->ctx == NULL) {
        EcValidator_destroy(v);

        return NULL;
    }

    return v;
}

void EcValidator_destroy(EcValidator* v) {
    if (v == NULL) {
        return;
    }

    if (v->ctx != NULL) {
        BN_CTX_free(v->ctx);
    }

    if (v->curr_point != NULL) {
        EC_POINT_free(v->curr_point);
    }

    free(v);
}

HashValidator* HashValidator_create(const EVP_MD* md, const unsigned char* client_digest,
                                    size_t digest_size, const unsigned char* salt,
                                    size_t salt_size) {
    HashValidator* v = malloc(sizeof(*v));

    if (v == NULL || md == NULL || client_digest == NULL || (salt == NULL && salt_size != 0) ||
        (salt != NULL && salt_size == 0)) {
        HashValidator_destroy(v);

        return NULL;
    }

    v->md = md;
    v->nid = EVP_MD_nid(md);
    v->is_xof = md == EVP_shake128() || md == EVP_shake256();
    v->digest_size = v->is_xof ? EVP_MD_size(md) : digest_size;
    v->client_digest = client_digest;
    v->salt = salt;
    v->salt_size = salt_size;
    v->curr_digest = malloc(v->digest_size * sizeof(*(v->curr_digest)));
    v->ctx = EVP_MD_CTX_new();

    if (v->curr_digest == NULL || v->ctx == NULL) {
        HashValidator_destroy(v);

        return NULL;
    }

    if (salt_size == 0) {
        EVP_MD_CTX_set_flags(v->ctx, EVP_MD_CTX_FLAG_ONESHOT);
    }

    return v;
}

void HashValidator_destroy(HashValidator* v) {
    if (v == NULL) {
        return;
    }

    if (v->ctx != NULL) {
        EVP_MD_CTX_free(v->ctx);
    }

    if (v->curr_digest != NULL) {
        free(v->curr_digest);
    }

    free(v);
}

Kang12Validator* Kang12Validator_create(const unsigned char* client_digest, size_t digest_size,
                                        const unsigned char* salt, size_t salt_size) {
    Kang12Validator* v = malloc(sizeof(*v));

    if (v == NULL || client_digest == NULL || digest_size == 0 ||
        (salt == NULL && salt_size != 0) || (salt != NULL && salt_size == 0)) {
        Kang12Validator_destroy(v);

        return NULL;
    }

    v->digest_size = digest_size;
    v->client_digest = client_digest;
    v->salt = salt;
    v->salt_size = salt_size;
    v->curr_digest = malloc(v->digest_size * sizeof(*(v->curr_digest)));

    return v;
}

void Kang12Validator_destroy(Kang12Validator* v) {
    if (v == NULL) {
        return;
    }

    if (v->curr_digest != NULL) {
        free(v->curr_digest);
    }

    free(v);
}

/// Given a starting permutation, iterate forward through every possible permutation until one
/// that's matching last_perm is found, or until a matching cipher is found.
/// \param client_key An allocated corrupted host_seed to fill if the corrupted host_seed was
/// found. Must be at least 32 bytes big.
/// \param host_seed The original AES host_seed.
/// \param client_cipher The client cipher (16 bytes) to test against.
/// \param userId A uuid_t that's used as the plaintext to encrypt.
/// \param first_perm The permutation to start iterating from.
/// \param last_perm The final permutation to stop iterating at, inclusively.
/// \param signal A pointer to a shared value. Used to signal the function to prematurely leave.
/// \param all If benchmark mode is set to a non-zero value, then continue even if found.
/// \param validated_keys A counter to keep track of how many keys were traversed. If NULL, then
/// this is skipped.
/// \return Returns a 1 if found or a 0 if not. Returns a -1 if an error has
/// occurred.
int findMatchingSeed(unsigned char* client_seed, const unsigned char* host_seed,
                     const mpz_t first_perm, const mpz_t last_perm, int all,
                     long long int* validated_keys,
#ifdef USE_MPI
                     int* signal, int verbose, int my_rank, int nprocs,
#else
                     const int* signal,
#endif
                     int (*crypto_func)(const unsigned char*, void*), int (*crypto_cmp)(void*),
                     void* crypto_args) {
    // Declaration
    int status = 0, cmp_status = 1;
    SeedIter iter;
    const unsigned char* curr_seed;
#ifdef USE_MPI
    int probe_flag = 0;
    long long int iter_count = 0;

    MPI_Request* requests;
    MPI_Status* statuses;

    if ((requests = malloc(nprocs * sizeof(*(requests)))) == NULL) {
        return -1;
    }

    if ((statuses = malloc(nprocs * sizeof(*(statuses)))) == NULL) {
        free(requests);

        return -1;
    }
#endif

    SeedIter_init(&iter, host_seed, SEED_SIZE, first_perm, last_perm);

    while (!SeedIter_end(&iter) && (all || !(*signal))) {
        if (validated_keys != NULL) {
            ++(*validated_keys);
        }
        curr_seed = SeedIter_get(&iter);

        // If crypto_func fails for some reason, break prematurely.
        if (crypto_func  != NULL && crypto_func (curr_seed, crypto_args)) {
            status = -1;
            break;
        }

        // If crypto_cmp fails for some reason, break prematurely.
        if (crypto_cmp != NULL && (cmp_status = crypto_cmp(crypto_args)) < 0) {
            status = -1;
            break;
        }

        // If the new crypto output is the same as the passed in client crypto output, set status to
        // true and break
        if (cmp_status == 0) {
            status = 1;

#ifdef USE_MPI
            *signal = 1;

            if (verbose) {
                fprintf(stderr, "INFO: Found by rank: %d, alerting ranks ...\n", my_rank);
            }

            memcpy(client_seed, curr_seed, SEED_SIZE);

            if (!all) {
                // alert all ranks that the key was found, including yourself
                for (int i = 0; i < nprocs; i++) {
                    if (i != my_rank) {
                        MPI_Isend(signal, 1, MPI_INT, i, 0, MPI_COMM_WORLD, &(requests[i]));
                    }
                }

                for (int i = 0; i < nprocs; i++) {
                    if (i != my_rank) {
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
            if (!all) {
                break;
            }
#endif
        }

#ifdef USE_MPI
        if (!all && !(*signal) && iter_count % 128 == 0) {
            MPI_Iprobe(MPI_ANY_SOURCE, 0, MPI_COMM_WORLD, &probe_flag, MPI_STATUS_IGNORE);

            if (probe_flag) {
                MPI_Recv(signal, 1, MPI_INT, MPI_ANY_SOURCE, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
            }
        }
#endif

        SeedIter_next(&iter);
    }

#ifdef USE_MPI
    free(requests);
    free(statuses);
#endif

    return status;
}
