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

void gmp_progression(unsigned char *key, size_t key_size, size_t mismatches) {
    unsigned char *corrupted_key;
    corrupted_key = malloc(sizeof(*corrupted_key) * key_size);

    uuid_t userId;
    char uuid[37];
    unsigned char cipher[sizeof(userId) + EVP_MAX_BLOCK_LENGTH];
    int outlen;

    uuid_generate(userId);
    uuid_unparse(userId, uuid);
    printf("Using UUID: %s\n", uuid);

    // Starting mismatch key
    mpz_t perm, t, tmp, next_perm, max_perm, key_mpz, corrupted_key_mpz;
    mpz_inits(perm, t, tmp, next_perm, max_perm, key_mpz, corrupted_key_mpz, NULL);

    // Convert key as unsigned char array to mpz
    mpz_import(key_mpz, key_size, 1, sizeof(*key), 0, 0, key);

    // Set perm to first key
    // Equivalent to: (perm << mismatches) - 1
    mpz_set_ui(tmp, 1);
    mpz_mul_2exp(tmp, tmp, mismatches);
    mpz_sub_ui(perm, tmp, 1);

    // Set max_perm to maximum possible permutation
    mpz_set(max_perm, perm);
    mpz_mul_2exp(max_perm, max_perm, (key_size * 8) - mismatches);

    // gmp_printf("%Zd\n", perm);
    while(mpz_cmp(perm, max_perm) != 0) {
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

        encrypt(corrupted_key, userId, sizeof(userId), cipher, &outlen);
    }

    mpz_clears(perm, t, tmp, next_perm, max_perm, key_mpz, corrupted_key_mpz, NULL);
    free(corrupted_key);
}

int main() {
    const size_t KEY_SIZE = 32;
    const size_t MISMATCHES = 4;

    unsigned char *key;
    key = malloc(sizeof(*key) * KEY_SIZE);

    clock_t startTime = clock();
    // int_progression(MISMATCHES);
    gmp_progression(key, KEY_SIZE, MISMATCHES);
    clock_t duration = clock() - startTime;

    printf("Clock time: %f s\n", (double)duration / CLOCKS_PER_SEC);

    free(key);

    return 0;
}