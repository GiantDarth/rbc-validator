//
// Created by cp723 on 3/14/2019.
//

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>

#include "crypto/aes256-ni_enc.h"

void print_hex(const unsigned char *array, size_t count) {
    for(size_t i = 0; i < count; i++) {
        printf("%02x", array[i]);
    }
}

int main() {
    const unsigned char key[] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    // A message that's exactly 16 bytes long.
    const char msg[] = "Hello world x2!\n";
    const unsigned char expected_cipher[] = {
            0x00, 0x80, 0xb5, 0xcd, 0x7d, 0x63, 0x1b, 0x04,
            0x25, 0x8a, 0xa4, 0x38, 0x55, 0x33, 0x1b, 0x3e
    };

    unsigned char cipher[AES_BLOCK_SIZE];
    int status;

    if(aes256_ecb_encrypt(cipher, key, (const unsigned char*)msg, strlen(msg))) {
        fprintf(stderr, "ERROR: evp_encrypt failed\n");
        return EXIT_FAILURE;
    }

    printf("Encryption: Test ");
    if(!memcmp(cipher, expected_cipher, sizeof(cipher))) {
        printf("Passed\n");
        status = EXIT_SUCCESS;
    }
    else {
        printf("Failed\n");
        status = EXIT_FAILURE;
    }

    print_hex(cipher, sizeof(cipher));
    printf("\n");

    print_hex(expected_cipher, sizeof(expected_cipher));
    printf("\n");

    return status;
}