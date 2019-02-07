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

/// Based on https://cs.stackexchange.com/a/67669
/// \param perm The permutation to set.
/// \param ordinal The ordinal as the input.
/// \param mismatches How many bits to set.
/// \param key_size How big the bit string is (in bytes)
void decode_ordinal(mpz_t perm, mpz_t ordinal, size_t mismatches, size_t key_size) {
    mpz_t binom;
    mpz_init(binom);

    mpz_set_ui(perm, 0);
    for (unsigned long bit = key_size * 8 - 1; mismatches > 0; bit--)
    {
        mpz_bin_uiui(binom, bit, mismatches);
        if (mpz_cmp(ordinal, binom) >= 0)
        {
            mpz_sub(ordinal, ordinal, binom);
            mpz_setbit(perm, bit);
            mismatches--;
        }
    }

    mpz_clear(binom);
}

/// Generate a set of starting permutations based on mismatches and a maximum key_size.
/// \param starting_perms The pre-allocated, pre-initialized array of starting_perms to fill.
/// \param starting_perms_size The count of starting_perms.
/// \param mismatches The hamming distance to base on (equivalent to # of bits set).
/// \param key_size The # of bytes the permutations will be.
void generate_starting_permutations(mpz_t *starting_perms, size_t starting_perms_size, size_t mismatches,
        size_t key_size) {
    // Always set the first one to the global first permutation
    gmp_assign_first_permutation(starting_perms[0], mismatches);

    mpz_t ordinal, chunk_size;
    mpz_inits(ordinal, chunk_size, NULL);

    mpz_bin_uiui(chunk_size, key_size * 8, mismatches);
    mpz_tdiv_q_ui(chunk_size, chunk_size, starting_perms_size);

    for(size_t i = 0; i < starting_perms_size; i++) {
        mpz_mul_ui(ordinal, chunk_size, i);
        gmp_printf("%Zd\n", ordinal);

        decode_ordinal(starting_perms[i], ordinal, mismatches, key_size);
    }

    mpz_clears(ordinal, chunk_size, NULL);
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
/// \param last_perm The final permutation to stop iterating at, inclusively.
/// \param key The original AES key.
/// \param key_size The key size in # of bytes, typically 32.
/// \param userId A uuid_t that's used to as the message to encrypt.
void gmp_progression(const mpz_t starting_perm, const mpz_t last_perm, const unsigned char *key,
        size_t key_size, uuid_t userId) {
    mpz_t key_mpz;
    unsigned char *corrupted_key;
    unsigned char cipher[sizeof(userId) + EVP_MAX_BLOCK_LENGTH];
    int outlen;

    // Initialization
    gmp_key_iter iter;
    gmp_key_iter_create(&iter, key, key_size, starting_perm, last_perm);

    // Memory allocation
    mpz_init(key_mpz);
    corrupted_key = malloc(sizeof(*corrupted_key) * key_size);

    // Convert key as unsigned char array to mpz
    mpz_import(key_mpz, key_size, 1, sizeof(*key), 0, 0, key);

    // While we haven't reached the end of iteration
    while(!gmp_key_iter_check(&iter)) {
        gmp_key_iter_get(&iter, corrupted_key);
        // If encryption fails for some reason, break prematurely.
        if(!encrypt(corrupted_key, userId, sizeof(userId), cipher, &outlen)) {
            break;
        }

        gmp_key_iter_next(&iter);
    }

    // Cleanup
    free(corrupted_key);
    mpz_clear(key_mpz);
    gmp_key_iter_destroy(&iter);
}

int main() {
    const size_t KEY_SIZE = 32;
    const size_t MISMATCHES = 4;

    unsigned char *key;
    key = malloc(sizeof(*key) * KEY_SIZE);

    size_t starting_perms_size = 512ULL;

    mpz_t *starting_perms;
    starting_perms = malloc(sizeof(*starting_perms) * starting_perms_size);
    for(size_t i = 0; i < starting_perms_size; i++) {
        mpz_init(starting_perms[i]);
    }

    mpz_t last_perm;
    mpz_init(last_perm);
    gmp_assign_last_permutation(last_perm, MISMATCHES, KEY_SIZE);

    generate_starting_permutations(starting_perms, starting_perms_size, MISMATCHES, KEY_SIZE);

    uuid_t userId;
    char uuid[37];

    uuid_generate(userId);
    uuid_unparse(userId, uuid);
    printf("Using UUID: %s\n", uuid);

    double startTime = omp_get_wtime();
    // int_progression(MISMATCHES);
    // Loop through every starting_perms, assuming that the array is already sorted.
    // Apparently the loop variable needs to be declared first and set as 'private(n)' for pure C?
    // (Needs to be checked on)
    size_t n;
    #pragma omp parallel for private(n) schedule(dynamic)
    for(n = 0; n < starting_perms_size; n++) {
        // If not the last of the starting_perms, set the last_perm to be the next item in the array
        if(n < starting_perms_size - 1) {
            gmp_progression(starting_perms[n], starting_perms[n + 1], key, KEY_SIZE, userId);
        }
            // Else, assume the last starting_perm will continue until last_perm.
        else {
            gmp_progression(starting_perms[n], last_perm, key, KEY_SIZE, userId);
        }
    }

    double duration = omp_get_wtime() - startTime;

    printf("Clock time: %f s\n", duration);

    mpz_clear(last_perm);
    for(size_t i = 0; i < starting_perms_size; i++) {
        mpz_clear(starting_perms[i]);
    }
    free(starting_perms);
    free(key);

    return 0;
}