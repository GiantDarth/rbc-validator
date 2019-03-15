//
// Created by cp723 on 3/14/2019.
//

#include <stdio.h>
#include <memory.h>
#include "aes256-ni.h"
#include "util.h"

void print_hex(const unsigned char *array, size_t count) {
    for(size_t i = 0; i < count; i++) {
        printf("%02x", array[i]);
    }
}

int main(int argc, char **argv) {
    const unsigned char key[] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f

    };
    const char msg[] = "Hello world x2!";
    const unsigned char expected_cipher[] = {
            0x58, 0x3a, 0x95, 0x74, 0x4d, 0xbe, 0x80, 0x4a,
            0xfc, 0x1d, 0x45, 0xbe, 0xb9, 0xbb, 0xfe, 0xf7
    };

    unsigned char cipher[16];

    aes256_enc_key_scheduler *key_scheduler = aes256_enc_key_scheduler_create();
    aes256_enc_key_scheduler_update(key_scheduler, key);

    aes256_ecb_encrypt(cipher, key_scheduler, (const unsigned char*)msg, 16);

    print_hex(cipher, 16);
    printf("\n");

    return memcmp(cipher, expected_cipher, 16) ? EXIT_FAILURE : EXIT_SUCCESS;
}