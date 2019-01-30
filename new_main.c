#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

#include <openssl/opensslv.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <uuid/uuid.h>
#include <gmp.h>
#include <omp.h>

/// Assigns the first possible permutation for a given # of mismatches.
/// \param perm A pre-allocated mpz_t to fill the permutation to.
/// \param mismatches The hamming distance that you want to base the permutation on.
void assign_first_permutation(mpz_t *perm, size_t mismatches) {
    // Set perm to first key
    // Equivalent to: (perm << mismatches) - 1
    mpz_set_ui(*perm, 1);
    mpz_mul_2exp(*perm, *perm, mismatches);
    mpz_sub_ui(*perm, *perm, 1);
}

/// Assigns the first possible permutation for a given # of mismatches and key size
/// \param perm A pre-allocated mpz_t to fill the permutation to.
/// \param mismatches The hamming distance that you want to base the permutation on.
/// \param key_size How big the relevant key is in # of bytes.
void assign_last_permutation(mpz_t *perm, size_t mismatches, size_t key_size) {
    // First set the value to the first permutation.
    assign_first_permutation(perm, mismatches);
    // Equivalent to: perm << ((key_size * 8) - mismatches)
    // E.g. if key_size = 32 and mismatches = 5, then there are 256-bits
    // Then we want to shift left 256 - 5 = 251 times.
    mpz_mul_2exp(*perm, *perm, (key_size * 8) - mismatches);
}

/// Encrypts some message data using AES-256-ECB w/ PCKS#7 padding
/// \param key The key data, must be at least 32 bytes long.
/// \param msg The message to be encrypted, designated to be msgLen bytes long.
/// \param msgLen Denotes the size of the message (not NULL-terminated).
/// \param cipher The output data's length (not NULL-terminated).
/// \return Returns 1 on success or 0 on error (typically OpenSSL error).
int encrypt(const unsigned char* key, const unsigned char* msg, size_t msgLen, unsigned char* cipher, int* outlen) {
    int tmplen;

    EVP_CIPHER_CTX *ctx;

    if((ctx = EVP_CIPHER_CTX_new()) == NULL) {
        return 0;
    }

    if(!EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL)) {
        fprintf(stderr, "ERROR: EVP_EncryptInit_ex failed.\nOpenSSL Error: %s\n",
                ERR_error_string(ERR_get_error(), NULL));
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    if(!EVP_EncryptUpdate(ctx, cipher, outlen, msg, (int)msgLen)) {
        fprintf(stderr, "ERROR: EVP_EncryptUpdate failed.\nOpenSSL Error: %s\n",
                ERR_error_string(ERR_get_error(), NULL));
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    if(!EVP_EncryptFinal_ex(ctx, cipher + *outlen, &tmplen)) {
        fprintf(stderr, "ERROR: EVP_EncryptFinal_ex failed.\nOpenSSL Error: %s\n",
                ERR_error_string(ERR_get_error(), NULL));
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    *outlen += tmplen;

    EVP_CIPHER_CTX_free(ctx);

    return 1;
}

void int_progression(size_t mismatches) {
    // Starting mismatch key
    unsigned int perm = (1 << mismatches) - 1, t;

    // printf("%u\n", perm);
    while(__builtin_ctz(perm) < (sizeof(perm) * 8) - mismatches) {
        t = perm | (perm - 1); // t gets v's least significant 0 bits set to 1
        // Next set to 1 the most significant bit to change, 
        // set to 0 the least significant ones, and add the necessary 1 bits.
        perm = (t + 1) | (((~t & -~t) - 1) >> (__builtin_ctz(perm) + 1));

        t = (perm | (perm - 1)) + 1;  
        perm = t | ((((t & -t) / (perm & -perm)) >> 1) - 1);  

        // printf("%u\n", perm);
    }
}

/// Given a starting permutation, iterate forward through every possible permutation until one that's matching
/// last_perm is found. With each new permutation, encrypt the given userId.
/// \param starting_perm The permutation to start iterating from.
/// \param last_perm The final permutation to stop iterating at.
/// \param key
/// \param key_size
/// \param mismatches
/// \param userId A uuid_t that's used to as the message to encrypt.
void gmp_progression(mpz_t starting_perm, mpz_t last_perm, const unsigned char *key, size_t key_size, uuid_t userId) {
    unsigned char *corrupted_key;
    corrupted_key = malloc(sizeof(*corrupted_key) * key_size);

    unsigned char cipher[sizeof(userId) + EVP_MAX_BLOCK_LENGTH];
    int outlen;

    // Starting mismatch key
    mpz_t perm, t, tmp, next_perm, key_mpz, corrupted_key_mpz;
    mpz_inits(perm, t, tmp, next_perm, key_mpz, corrupted_key_mpz, NULL);

    // Copy the initial perm from starting_perm
    mpz_set(perm, starting_perm);

    // Convert key as unsigned char array to mpz
    mpz_import(key_mpz, key_size, 1, sizeof(*key), 0, 0, key);

    // gmp_printf("%Zd\n", perm);
    while(mpz_cmp(perm, last_perm) <= 0) {
        // Equivalent to: t = (perm | (perm - 1)) + 1
        mpz_sub_ui(next_perm, perm, 1);
        mpz_ior(t, perm, next_perm);
        mpz_add_ui(t, t, 1);

        // Equivalent to: perm = t | ((((t & -t) / (perm & -perm)) >> 1) - 1)
        mpz_neg(next_perm, perm);
        mpz_and(next_perm, perm, next_perm);

        mpz_neg(tmp, t);
        mpz_and(tmp, t, tmp);

        // Truncate divide
        mpz_tdiv_q(next_perm, tmp, next_perm);
        // Right shift by 1
        mpz_tdiv_q_2exp(next_perm, next_perm, 1);
        mpz_sub_ui(next_perm, next_perm, 1);
        mpz_ior(perm, t, next_perm);

        // gmp_printf("%Zd\n", perm);

        // Convert from mpz to an unsigned char array
        mpz_and(corrupted_key_mpz, key_mpz, perm);
        mpz_neg(corrupted_key_mpz, key_mpz);
        mpz_export(corrupted_key, NULL, sizeof(*corrupted_key), 1, 0, 0, corrupted_key_mpz);

        // If encryption fails for some reason, break prematurely.
        if(!encrypt(corrupted_key, userId, sizeof(userId), cipher, &outlen)) {
            break;
        }
    }

    mpz_clears(perm, t, tmp, next_perm, key_mpz, corrupted_key_mpz, NULL);
    free(corrupted_key);
}

int main() {
    const size_t KEY_SIZE = 32;
    const size_t MISMATCHES = 4;

    unsigned char *key;
    key = malloc(sizeof(*key) * KEY_SIZE);

    uuid_t userId;
    char uuid[37];

    uuid_generate(userId);
    uuid_unparse(userId, uuid);
    printf("Using UUID: %s\n", uuid);

    mpz_t starting_perm, last_perm;
    mpz_inits(starting_perm, last_perm, NULL);

    assign_first_permutation(&starting_perm, MISMATCHES);
    assign_last_permutation(&last_perm, MISMATCHES, KEY_SIZE);

    clock_t startTime = clock();
    // int_progression(MISMATCHES);
    gmp_progression(starting_perm, last_perm, key, KEY_SIZE, userId);
    clock_t duration = clock() - startTime;

    printf("Clock time: %f s\n", (double)duration / CLOCKS_PER_SEC);

    mpz_clears(starting_perm, last_perm, NULL);
    free(key);

    return 0;
}