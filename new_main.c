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

/// Generate a new random permutation based on mismatches and a maximum key_size.
/// \param perm The pre-allocated permutation to fill.
/// \param mismatches The hamming distance to base on (equivalent to # of bits set).
/// \param key_size The # of bytes the permutation will be.
void generate_random_permutation(mpz_t *perm, size_t mismatches, size_t key_size) {
    if(mismatches > key_size * 8) {
        fprintf(stderr, "ERROR: key_size too large to fit into random permutation.\n");
        return;
    }

    // Use an unsigned char array as equivalently to an array of unique random 0-255 values
    // Each value basically tells which bit index to set on the permutation, so each value must be unique.
    unsigned char indices[mismatches];
    size_t count = 0;
    // Assumes using a UNIX platform (more specifically Linux).
    FILE *fd = fopen("/dev/urandom", "r");

    int found = 0;
    while(count < mismatches) {
        // Fill in a new random byte (equivalent to a random 0 - 255 integer).
        fread(&(indices[count]), sizeof(indices[count]), 1, fd);
        // Iterate through every previous index and ensure the new one is unique.
        for(size_t i = 0; i < count; i++) {
            if(indices[count] == indices[i]) {
                found = 1;
            }
        }

        // Only increment the count when a unique index is found.
        if(!found) {
            count++;
        }
        else {
            found = 0;
        }
    }

    // Initialize the permutation to 0.
    mpz_set_ui(*perm, 0);
    // Go through every index and set that bit on the permutation.
    for(size_t i = 0; i < mismatches; i++) {
        mpz_setbit(*perm, indices[i]);
    }
}

/// Use simple insertion sort to sort the permutations.
/// \param perms A preallocated array of permutations. This will be swapped in-place.
/// \param perms_size How big the array is.
void sort_permutations(mpz_t *perms, size_t perms_size) {
    mpz_t tmp;
    mpz_init(tmp);

    for(size_t i = 1; i < perms_size; i++) {
        for(size_t j = i; j > 0 && mpz_cmp(perms[j - 1], perms[j]) > 0; j--) {
            mpz_set(tmp, perms[j - 1]);
            mpz_set(perms[j - 1], perms[j]);
            mpz_set(perms[j], tmp);
        }
    }
}

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
/// \param last_perm The final permutation to stop iterating at, inclusively.
/// \param key The original AES key.
/// \param key_size The key size in # of bytes, typically 32.
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

    size_t starting_perms_size = 512ULL;

    mpz_t *starting_perms;
    starting_perms = malloc(sizeof(*starting_perms) * starting_perms_size);
    for(size_t i = 0; i < starting_perms_size; i++) {
        mpz_init(starting_perms[i]);
    }

    mpz_t last_perm;
    mpz_init(last_perm);
    assign_last_permutation(&last_perm, MISMATCHES, KEY_SIZE);

    // Always set the first one to the global first permutation
    assign_first_permutation(&(starting_perms[0]), MISMATCHES);
    size_t perm_count = 1;
    int perm_found = 0;
    while(perm_count < starting_perms_size) {
        generate_random_permutation(&(starting_perms[perm_count]), MISMATCHES, KEY_SIZE);
        for(size_t i = 0; i < perm_count; i++) {
            if(mpz_cmp(starting_perms[i], starting_perms[perm_count]) == 0) {
                perm_found = 1;
                break;
            }
        }

        if(!perm_found) {
            perm_count++;
        }
        else {
            perm_found = 0;
        }
    }

    sort_permutations(starting_perms, starting_perms_size);

    uuid_t userId;
    char uuid[37];

    uuid_generate(userId);
    uuid_unparse(userId, uuid);
    printf("Using UUID: %s\n", uuid);

    clock_t startTime = clock();
    // int_progression(MISMATCHES);
    // Loop through every starting_perms, assuming that the array is already sorted.
    // Apparently the loop variable needs to be declared first and set as 'private(n)' for pure C?
    // (Needs to be checked on)
    size_t n;
    // #pragma omp parallel for private(n)
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

    clock_t duration = clock() - startTime;

    printf("Clock time: %f s\n", (double)duration / CLOCKS_PER_SEC);

    mpz_clear(last_perm);
    for(size_t i = 0; i < starting_perms_size; i++) {
        mpz_clear(starting_perms[i]);
    }
    free(starting_perms);
    free(key);

    return 0;
}