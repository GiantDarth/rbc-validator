
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>

#include <openssl/err.h>

#include "crypto/ec.h"

void print_hex(const unsigned char *array, size_t count) {
    for(size_t i = 0; i < count; i++) {
        printf("%02x", array[i]);
    }
}

int main() {
    unsigned char private_key[ECC_PRIV_KEY_SIZE] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };

    unsigned char expected_public_key_buffer[ECC_PUB_KEY_SIZE] = {
            0x7a, 0x59, 0x31, 0x80, 0x86, 0x0c, 0x40, 0x37,
            0xc8, 0x3c, 0x12, 0x74, 0x98, 0x45, 0xc8, 0xee,
            0x14, 0x24, 0xdd, 0x29, 0x7f, 0xad, 0xcb, 0x89,
            0x5e, 0x35, 0x82, 0x55, 0xd2, 0xc7, 0xd2, 0xb2,
            0xa8, 0xca, 0x25, 0x58, 0x0f, 0x26, 0x26, 0xfe,
            0x57, 0x90, 0x62, 0xff, 0x1b, 0x99, 0xff, 0x91,
            0xc2, 0x4a, 0x0d, 0xa0, 0x6f, 0xb3, 0x2b, 0x5b,
            0xe2, 0x01, 0x48, 0xc9, 0x24, 0x9f, 0x56, 0x50
    };

    char *hex;

    EC_GROUP *group;
    EC_POINT *point, *expected_point;
    BN_CTX *ctx;
    BIGNUM *scalar;

    int status, cmp_status;

    if((group = EC_GROUP_new_by_curve_name(ECC_CURVE)) == NULL) {
        fprintf(stderr, "ERROR: EC_GROUP_new_by_curve_name failed.\nOpenSSL Error: %s\n",
                ERR_error_string(ERR_get_error(), NULL));

        return EXIT_FAILURE;
    }

    if((point = EC_POINT_new(group)) == NULL) {
        fprintf(stderr, "ERROR: EC_POINT_new failed.\nOpenSSL Error: %s\n",
                ERR_error_string(ERR_get_error(), NULL));

        EC_GROUP_free(group);

        return EXIT_FAILURE;
    }

    if((expected_point = EC_POINT_new(group)) == NULL) {
        fprintf(stderr, "ERROR: EC_POINT_new failed.\nOpenSSL Error: %s\n",
                ERR_error_string(ERR_get_error(), NULL));

        EC_POINT_free(point);
        EC_GROUP_free(group);

        return EXIT_FAILURE;
    }

    if((ctx = BN_CTX_new()) == NULL) {
        fprintf(stderr, "ERROR: BN_CTX_new failed.\nOpenSSL Error: %s\n",
                ERR_error_string(ERR_get_error(), NULL));

        EC_POINT_free(expected_point);
        EC_POINT_free(point);
        EC_GROUP_free(group);

        return EXIT_FAILURE;
    }

    BN_CTX_start(ctx);

    if((scalar = BN_CTX_get(ctx)) == NULL) {
        fprintf(stderr, "ERROR: BN_CTX_get failed.\nOpenSSL Error: %s\n",
                ERR_error_string(ERR_get_error(), NULL));

        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
        EC_POINT_free(expected_point);
        EC_POINT_free(point);
        EC_GROUP_free(group);

        return EXIT_FAILURE;
    }

    BN_bin2bn(private_key, ECC_PRIV_KEY_SIZE, scalar);

    if(!EC_POINT_mul(group, point, scalar, NULL, NULL, ctx)) {
        fprintf(stderr, "ERROR: ECC_POINT_mul failed.\nOpenSSL Error: %s\n",
                ERR_error_string(ERR_get_error(), NULL));

        status = EXIT_FAILURE;
    }
    else {
        set_ec_point(point, ctx, public_key, group);
        set_ec_point(expected_point, ctx, )

        if((cmp_status = EC_POINT_cmp(group, point, client_point, ctx)) < 0) {
            fprintf(stderr, "ERROR: EC_POINT_cmp failed.\nOpenSSL Error: %s\n",
                    ERR_error_string(ERR_get_error(), NULL));

            status = EXIT_FAILURE;
            goto cleanup;
        }

        printf("Public Key Generation: Test ");
        if(!cmp_status) {
            printf("Passed\n");
            status =  EXIT_SUCCESS;
        }
        else {
            printf("Failed\n");
            status = EXIT_FAILURE;
        }

        if((hex = EC_POINT_point2hex(group, point, POINT_CONVERSION_UNCOMPRESSED, ctx) == NULL) {
            }

            printf("%s\n", hex);
            OPENSSL_free(hex);

            if((hex = EC_POINT_point2hex(group, expected_point, POINT_CONVERSION_UNCOMPRESSED,
                                     ctx))
            printf("%s\n", hex);
            OPENSSL_free(hex);
        }



    }


cleanup:
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    EC_POINT_free(expected_point);
    EC_POINT_free(point);
    EC_GROUP_free(group);

    return status;
}
