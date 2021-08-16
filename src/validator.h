//
// Created by chaos on 2/23/2021.
//

#ifndef RBC_VALIDATOR_VALIDATOR_H_
#define RBC_VALIDATOR_VALIDATOR_H_

#include <gmp.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <stdlib.h>

#include "crypto/aes256-ni_enc.h"

typedef struct CipherValidator {
    const EVP_CIPHER* evp_cipher;
    EVP_CIPHER_CTX* ctx;
    size_t msg_size;
    const unsigned char *msg, *client_cipher, *iv;
    unsigned char* curr_cipher;
} CipherValidator;

typedef struct EcValidator {
    const EC_GROUP* group;
    const EC_POINT* client_point;
    EC_POINT* curr_point;
    BN_CTX* ctx;
} EcValidator;

typedef struct HashValidator {
    const EVP_MD* md;
    int is_xof;
    int nid;
    size_t digest_size, salt_size;
    EVP_MD_CTX* ctx;
    const unsigned char *client_digest, *salt;
    unsigned char* curr_digest;
} HashValidator;

typedef struct Kang12Validator {
    size_t digest_size, salt_size;
    const unsigned char *client_digest, *salt;
    unsigned char* curr_digest;
} Kang12Validator;

int CryptoFunc_aes256(const unsigned char* curr_seed, void* args);
int CryptoCmp_aes256(void* args);

int CryptoFunc_cipher(const unsigned char* curr_seed, void* args);
int CryptoCmp_cipher(void* args);

CipherValidator* CipherValidator_create(const EVP_CIPHER* evp_cipher,
                                        const unsigned char* client_cipher,
                                        const unsigned char* msg, size_t msg_size,
                                        const unsigned char* iv);
void CipherValidator_destroy(CipherValidator* v);

int CryptoFunc_ec(const unsigned char* curr_seed, void* args);
int CryptoCmp_ec(void* args);

/// \param EC_GROUP The EC group to use
/// \param EC_POINT The client EC public key
EcValidator* EcValidator_create(const EC_GROUP* group, const EC_POINT* client_point);
void EcValidator_destroy(EcValidator* v);

HashValidator* HashValidator_create(const EVP_MD* md, const unsigned char* client_digest,
                                    size_t digest_size, const unsigned char* salt,
                                    size_t salt_size);
void HashValidator_destroy(HashValidator* v);

int CryptoFunc_hash(const unsigned char* curr_seed, void* args);
int CryptoCmp_hash(void* args);

Kang12Validator* Kang12Validator_create(const unsigned char* client_digest, size_t digest_size,
                                        const unsigned char* salt, size_t salt_size);
void Kang12Validator_destroy(Kang12Validator* v);

int CryptoFunc_kang12(const unsigned char* curr_seed, void* args);
int CryptoCmp_kang12(void* args);

/// Given a starting permutation, iterate forward through every possible permutation until one
/// that's matching last_perm is found, or until a matching crytographic output is found.
/// \param client_seed The output (potentially) corrupted client seed.
/// \param host_seed The original host seed.
/// \param first_perm The permutation to start iterating from.
/// \param last_perm The final permutation to stop iterating at, inclusively.
/// \param all If benchmark mode is set to a non-zero value, then continue even if found.
/// \param validated_keys A counter to keep track of how many keys were traversed. If NULL, then
/// this is skipped.
/// \param signal A pointer to a shared value. Used to signal the function to prematurely leave.
#ifdef USE_MPI
/// \param verbose A boolean on whether to print verbose output or not
/// \param my_rank This process's MPI rank
/// \param nprocs How many total MPI ranks there are
#endif
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
                     void* crypto_args);

#endif  // RBC_VALIDATOR_VALIDATOR_H_
