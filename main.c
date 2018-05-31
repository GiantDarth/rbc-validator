#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <uuid/uuid.h>

// Install (on Ubuntu): sudo apt-get install libssl-dev uuid-dev
// Uses API as of OpenSSL 1.0.2g

/// Encrypts some message data using AES-256-ECB w/ PCKS#7 padding
/// \param key The key data, must be at least 32 bytes long.
/// \param msg The message to be encrypted, designated to be msgLen bytes long.
/// \param msgLen Denotes the size of the message (not NULL-terminated).
/// \param cipher The output data's length (not NULL-terminated).
/// \return Returns 1 on success or 0 on error (typically OpenSSL error).
int encrypt(const unsigned char* key, const unsigned char* msg, size_t msgLen, unsigned char* cipher, int* outlen) {
    EVP_CIPHER_CTX ctx;
    int tmplen;

    EVP_CIPHER_CTX_init(&ctx);

    if(!EVP_EncryptInit_ex(&ctx, EVP_aes_256_ecb(), NULL, key, NULL)) {
        fprintf(stderr, "ERROR: EVP_EncryptInit_ex failed.\nOpenSSL Error: %s\n",
                ERR_error_string(ERR_get_error(), NULL));
        EVP_CIPHER_CTX_cleanup(&ctx);
        return 0;
    }

    if(!EVP_EncryptUpdate(&ctx, cipher, outlen, msg, (int)msgLen)) {
        fprintf(stderr, "ERROR: EVP_EncryptUpdate failed.\nOpenSSL Error: %s\n",
                ERR_error_string(ERR_get_error(), NULL));
        EVP_CIPHER_CTX_cleanup(&ctx);
        return 0;
    }
    if(!EVP_EncryptFinal_ex(&ctx, cipher + *outlen, &tmplen)) {
        fprintf(stderr, "ERROR: EVP_EncryptFinal_ex failed.\nOpenSSL Error: %s\n",
                ERR_error_string(ERR_get_error(), NULL));
        EVP_CIPHER_CTX_cleanup(&ctx);
        return 0;
    }
    *outlen += tmplen;

    if(!EVP_CIPHER_CTX_cleanup(&ctx)) {
        fprintf(stderr, "ERROR: EVP_CIPHER_CTX_cleanup failed.\nOpenSSL Error: %s\n",
                ERR_error_string(ERR_get_error(), NULL));
        return 0;
    }

    return 1;
}

int main() {
    const int ITERATIONS = 100;
    const size_t KEY_SIZE = 32;
    const size_t MISMATCHES = 3;

    const size_t KEY_SPACE_LENGTH = 2763520;

    unsigned char* keySpace;
    // Allocate and initialize the whole key space as 0 (necessary to set bits later).
    keySpace = calloc(KEY_SIZE * KEY_SPACE_LENGTH, sizeof(*keySpace));

    // Pre-generate all possible key derivatives that are 3-bits apart.
    // TODO: Generalize key space generation to any # of mismatches
    for(size_t i = 0, index = 0; i < KEY_SIZE - 2; ++i) {
        for(size_t j = i + 1; j < KEY_SIZE - 1; ++j) {
            for(size_t k = j + 1; k < KEY_SIZE; ++k, ++index) {
                keySpace[(index * KEY_SIZE) + (i / 8)] |= (unsigned char)0x1 << (i % 8);
                keySpace[(index * KEY_SIZE) + (j / 8)] |= (unsigned char)0x1 << (j % 8);
                keySpace[(index * KEY_SIZE) + (k / 8)] |= (unsigned char)0x1 << (k % 8);
            }
        }
    }

    uuid_t userId;
    char uuid[37];
    unsigned char cipher[sizeof(userId) + EVP_MAX_BLOCK_LENGTH];
    int outlen;

    printf("Running %d iterations...\n", ITERATIONS);
    clock_t duration = 0, startTime;
    // Run several iterations to get an average of runtime
    for(int iter = 0; iter < ITERATIONS; ++iter) {
        uuid_generate(userId);
        uuid_unparse(userId, uuid);
        printf("Using UUID: %s\n", uuid);

        // Ensures that UUID generation / "un"parsing isn't included in the benchmarking
        startTime = clock();
        for(size_t index = 0; index < KEY_SPACE_LENGTH; ++index) {
            encrypt(&(keySpace[index * KEY_SIZE]), userId, sizeof(userId), cipher, &outlen);
        }
        duration += clock() - startTime;
    }
    clock_t endTime = clock();

    printf("Clock time: %f s\n", (double)duration / CLOCKS_PER_SEC / ITERATIONS);

    free(keySpace);

    return 0;
}