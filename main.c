#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <uuid/uuid.h>

// Install (on Ubuntu): sudo apt-get install libssl-dev uuid-dev
// Uses API as of OpenSSL 1.0.2g

int min(int a, int b) {
    return (a < b) ? a : b;
}

/// Dynamic programming version of "n choose k"
/// Taken from https://www.geeksforgeeks.org/dynamic-programming-set-9-binomial-coefficient/
/// \param n
/// \param k
/// \return The binomial coefficient, aka. n choose k
long long binomialCoeff(int n, int k)
{
    long long C[k+1];
    memset(C, 0, sizeof(C));

    C[0] = 1;  // nC0 is 1

    for(int i = 1; i <= n; ++i)
    {
        // Compute next row of pascal triangle using
        // the previous row
        for(int j = min(i, k); j > 0; --j)
            C[j] = C[j] + C[j - 1];
    }

    return C[k];
}

void fillKeyspaceRec(unsigned char *keySpace, size_t keySize, size_t mismatches, size_t *count, size_t *values,
                 size_t startValue, size_t startIndex) {
    size_t i = startIndex, j;

    for(values[i] = startValue; values[i] <= (keySize * 8) - mismatches + startIndex; values[i]++) {
        if(startIndex == mismatches - 1) {
            for(int k = 0; k < mismatches; ++k) {
                keySpace[(*count * keySize) + (values[k] / 8)] |= 0x1 << (values[k] % 8);
            }
            ++(*count);
        }
        else {
            fillKeyspaceRec(keySpace, keySize, mismatches, count, values, values[i] + 1, startIndex + 1);
        }
    }
}

void fillKeyspace(unsigned char* keySpace, size_t keySize, size_t mismatches) {
//    size_t keySpaceLength = (size_t)binomialCoeff(keySize * 8, mismatches);
    size_t values[mismatches];
    size_t count = 0;

    fillKeyspaceRec(keySpace, keySize, mismatches, &count, values, 0, 0);
}

/// Encrypts some message data using AES-256-ECB w/ PCKS#7 padding
/// \param key The key data, must be at least 32 bytes long.
/// \param msg The message to be encrypted, designated to be msgLen bytes long.
/// \param msgLen Denotes the size of the message (not NULL-terminated).
/// \param cipher The output data's length (not NULL-terminated).
/// \return Returns 1 on success or 0 on error (typically OpenSSL error).
int encrypt(const unsigned char* key, const unsigned char* msg, size_t msgLen, unsigned char* cipher, int* outlen) {
    EVP_CIPHER_CTX *ctx;
    int tmplen;

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

int main() {
    const int ITERATIONS = 100;
    const size_t KEY_SIZE = 32;
    const size_t MISMATCHES = 4;

    size_t keySpaceLength = (size_t)binomialCoeff(KEY_SIZE * 8, MISMATCHES);

    unsigned char* keySpace;
    // Allocate and initialize the whole key space as 0 (necessary to set bits later).
    keySpace = calloc(KEY_SIZE * keySpaceLength, sizeof(*keySpace));

    // Pre-generate all possible key derivatives that are 3-bits apart.
    // TODO: Generalize key space generation to any # of mismatches
//    for(size_t i = 0, index = 0; i < KEY_SIZE - 2; ++i) {
//        for(size_t j = i + 1; j < KEY_SIZE - 1; ++j) {
//            for(size_t k = j + 1; k < KEY_SIZE; ++k, ++index) {
//                keySpace[(index * KEY_SIZE) + (i / 8)] |= (unsigned char)0x1 << (i % 8);
//                keySpace[(index * KEY_SIZE) + (j / 8)] |= (unsigned char)0x1 << (j % 8);
//                keySpace[(index * KEY_SIZE) + (k / 8)] |= (unsigned char)0x1 << (k % 8);
//            }
//        }
//    }

    fillKeyspace(keySpace, KEY_SIZE, MISMATCHES);

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
        for(size_t index = 0; index < keySpaceLength; ++index) {
            encrypt(&(keySpace[index * KEY_SIZE]), userId, sizeof(userId), cipher, &outlen);
        }
        duration += clock() - startTime;
    }

    printf("Clock time: %f s\n", (double)duration / CLOCKS_PER_SEC / ITERATIONS);

    free(keySpace);

    return 0;
}