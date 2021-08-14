//
// Created by cp723 on 3/14/2019.
//

#include "crypto/cipher.h"

#include <memory.h>
#include <stdio.h>
#include <stdlib.h>

#include "util.h"

int generic_test(const char* name, const EVP_CIPHER* evp_cipher, const unsigned char* key,
                 const unsigned char* msg, const unsigned char* expected_cipher, size_t msg_len,
                 const unsigned char* iv) {
    int status;
    unsigned char* cipher = malloc(msg_len);
    if (cipher == NULL) {
        return 1;
    }

    if (evp_encrypt(cipher, NULL, evp_cipher, key, (const unsigned char*)msg, msg_len, iv)) {
        fprintf(stderr, "ERROR: evp_encrypt failed\n");
        return EXIT_FAILURE;
    }

    printf("%s Encryption: Test ", name);
    if (!memcmp(cipher, expected_cipher, msg_len)) {
        printf("Passed\n");
        status = 0;
    } else {
        printf("Failed\n");
        status = 1;
    }

    printf("Expected: ");
    fprint_hex(stdout, expected_cipher, msg_len);
    printf("\n");

    printf("Actual:   ");
    fprint_hex(stdout, cipher, msg_len);
    printf("\n");

    free(cipher);

    return status;
}

#define TEST_SIZE 2

int main() {
    const unsigned char key[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                                 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                                 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
    // A message that's exactly 16 bytes long (excluding the null character)
    const char msg[] = "Hello world x2!\n";

    const EVP_CIPHER* evp_ciphers[TEST_SIZE] = {EVP_aes_256_ecb(), EVP_chacha20()};
    const char* names[TEST_SIZE] = {"AES-256-ECB", "ChaCha20"};
    const unsigned char expected_ciphers[TEST_SIZE][sizeof(msg) - 1] = {
            {0x00, 0x80, 0xb5, 0xcd, 0x7d, 0x63, 0x1b, 0x04, 0x25, 0x8a, 0xa4, 0x38, 0x55, 0x33,
             0x1b, 0x3e},
            {0x8f, 0xba, 0x63, 0x2c, 0x58, 0x8c, 0xec, 0xbe, 0x91, 0x2d, 0xd1, 0x6a, 0xcd, 0x24,
             0x54, 0xb4}};
    const unsigned char chacha20_iv[16] = {0x00, 0x00, 0x00, 0x00, 0x65, 0xda, 0x01, 0x76,
                                           0x39, 0x72, 0xe3, 0x5d, 0xfa, 0x28, 0x2e, 0xb8};
    const unsigned char* ivs[TEST_SIZE] = {NULL, chacha20_iv};

    int status = 0;

    for (size_t i = 0; i < TEST_SIZE; i++) {
        status |= generic_test(names[i], evp_ciphers[i], key, (unsigned char*)msg,
                               expected_ciphers[i], sizeof(msg) - 1, ivs[i]);
        if (i < TEST_SIZE - 1) {
            printf("\n");
        }
    }

    return status ? EXIT_FAILURE : EXIT_SUCCESS;
}