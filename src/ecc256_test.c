
#include <stdio.h>
#include <memory.h>
#include "util.h"
#include "../lib/micro-ecc/uECC.h"

#define	EXIT_FAILURE	1	/* Failing exit status.  */
#define	EXIT_SUCCESS	0	/* Successful exit status.  */

void print_hex(const unsigned char *array, size_t count) {
    for(size_t i = 0; i < count; i++) {
        printf("%02x", array[i]);
    }
}

int main(int argc, char **argv) {
    unsigned char priKey[] = { // 32 bytes long
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };

    if (argc > 1) {
        if (strlen(argv[1]) != 32*2) {
            fprintf(stderr, "ERROR: PRIV_KEY incorrect length %ld\n", strlen(argv[1]));
            return EXIT_FAILURE;
        }
        switch(parse_hex(priKey, argv[1])) {
            case 1:
                fprintf(stderr, "ERROR: PRIV_KEY had non-hexadecimal characters.\n");
                return EXIT_FAILURE;
            case 2:
                fprintf(stderr, "ERROR: PRIV_KEY did not have even length.\n");
                return EXIT_FAILURE;
            default:
                break;
        }

    }
    unsigned char pubKey[64];
    unsigned char signature[64];
    // A message that's exactly 16 bytes long.
    const char msg[] = "Hello world x2!\n";
    const struct uECC_Curve_t * curve = uECC_secp256r1();

    printf("0-ecc prikey:\n");
    print_hex(priKey, sizeof(priKey));
    printf("\n");

    // generate a ecc pub/pri key pare
    if (! uECC_compute_public_key(priKey, pubKey, curve)) {
        printf("ERROR uECC_compute_public_key - abort run");
        return EXIT_FAILURE;
    }

    printf("1-ecc pubkey:\n");
    print_hex(pubKey, sizeof(pubKey));
    printf("\n");

    // verify that ecc pubkey is valid for this curve
    if (! uECC_valid_public_key(pubKey, curve)) {
        printf("ERROR uECC_valid_public_key - abort run");
        return EXIT_FAILURE;
    }

    printf("2-ecc pubkey has been verified\n");

    if (! uECC_sign(priKey, (const uint8_t*)msg, sizeof(msg), signature, curve)) {
        printf("ERROR uECC_sign - abort run");
        return EXIT_FAILURE;
    }

    printf("3-ecdsa signature:\n");
    print_hex(signature, sizeof(signature));
    printf("\n");

    if (! uECC_verify(pubKey, (const uint8_t*)msg, sizeof(msg), signature, curve)) {
        printf("ERROR uECC_verify - abort run");
        return EXIT_FAILURE;
    }

    printf("4-ecdsa message + signature has been verified\n");

    return EXIT_SUCCESS;
}
