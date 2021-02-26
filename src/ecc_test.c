
#include <stdio.h>
#include <stdlib.h>

#include <openssl/err.h>

#include "crypto/ec.h"

#define EC_CURVE NID_X9_62_prime256v1
#define EC_PRIV_KEY_SIZE 32
#define EC_PUB_COMP_KEY_SIZE 33

typedef struct ec_test_wrapper {
    EC_GROUP *group;
    EC_POINT *point;
    EC_POINT *expected_point;
} ec_test_wrapper;

ec_test_wrapper* ec_test_wrapper_create();
void ec_test_wrapper_destroy(ec_test_wrapper *wrapper);

ec_test_wrapper* ec_test_wrapper_create() {
    ec_test_wrapper *wrapper;

    if((wrapper = malloc(sizeof(*wrapper))) == NULL) {
        return NULL;
    }

    if((wrapper->group = EC_GROUP_new_by_curve_name(EC_CURVE)) == NULL) {
        fprintf(stderr, "ERROR: EC_GROUP_new_by_curve_name failed.\nOpenSSL Error: %s\n",
                ERR_error_string(ERR_get_error(), NULL));

        ec_test_wrapper_destroy(wrapper);

        return NULL;
    }

    if((wrapper->point = EC_POINT_new(wrapper->group)) == NULL) {
        fprintf(stderr, "ERROR: EC_POINT_new failed.\nOpenSSL Error: %s\n",
                ERR_error_string(ERR_get_error(), NULL));

        ec_test_wrapper_destroy(wrapper);

        return NULL;
    }

    if((wrapper->expected_point = EC_POINT_new(wrapper->group)) == NULL) {
        fprintf(stderr, "ERROR: EC_POINT_new failed.\nOpenSSL Error: %s\n",
                ERR_error_string(ERR_get_error(), NULL));

        ec_test_wrapper_destroy(wrapper);

        return NULL;
    }

    return wrapper;
}

void ec_test_wrapper_destroy(ec_test_wrapper *wrapper) {
    // If wrapper is already NULL, escape early
    if (wrapper == NULL) {
        return;
    }

    if (wrapper->expected_point != NULL) {
        EC_POINT_free(wrapper->expected_point);
    }

    if (wrapper->point != NULL) {
        EC_POINT_free(wrapper->point);
    }

    if (wrapper->group != NULL) {
        EC_GROUP_free(wrapper->group);
    }

    free(wrapper);
}

int main() {
    unsigned char private_key[EC_PRIV_KEY_SIZE] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };

    // An ECC public key represented in compressed form (see Sec. 2.3.3 of the SECG SEC 1)
    unsigned char expected_public_key[EC_PUB_COMP_KEY_SIZE] = {
            // y-byte
            0x02,
            // x
            0x7a, 0x59, 0x31, 0x80, 0x86, 0x0c, 0x40, 0x37,
            0xc8, 0x3c, 0x12, 0x74, 0x98, 0x45, 0xc8, 0xee,
            0x14, 0x24, 0xdd, 0x29, 0x7f, 0xad, 0xcb, 0x89,
            0x5e, 0x35, 0x82, 0x55, 0xd2, 0xc7, 0xd2, 0xb2
    };

    ec_test_wrapper *test_wrapper;
    int status, cmp_status;

    if((test_wrapper = ec_test_wrapper_create()) == NULL) {
        return EXIT_FAILURE;
    }

    if(!EC_POINT_oct2point(test_wrapper->group, test_wrapper->expected_point, expected_public_key,
                           EC_PUB_COMP_KEY_SIZE, NULL)) {
        fprintf(stderr, "ERROR: EC_POINT_oct2point failed.\nOpenSSL Error: %s\n",
                ERR_error_string(ERR_get_error(), NULL));

        ec_test_wrapper_destroy(test_wrapper);

        return EXIT_FAILURE;
    }

    get_ec_public_key(test_wrapper->point, NULL, test_wrapper->group, private_key, EC_PRIV_KEY_SIZE);

    if((cmp_status = EC_POINT_cmp(test_wrapper->group, test_wrapper->point, test_wrapper->expected_point,
                                  NULL)) < 0) {
        fprintf(stderr, "ERROR: EC_POINT_cmp failed.\nOpenSSL Error: %s\n",
                ERR_error_string(ERR_get_error(), NULL));

        ec_test_wrapper_destroy(test_wrapper);

        status = EXIT_FAILURE;
    }

    printf("Public Key Generation: Test ");
    if(cmp_status == 0) {
        printf("Passed\n");
        status = EXIT_SUCCESS;
    }
    else {
        printf("Failed\n");
        status = EXIT_FAILURE;
    }

    printf("Expected Public Key: ");
    if(fprintf_ec_point(stdout, test_wrapper->group, test_wrapper->point,
                        POINT_CONVERSION_COMPRESSED, NULL)) {
        fprintf(stderr, "ERROR: fprintf_point failed.\n");

        ec_test_wrapper_destroy(test_wrapper);

        return EXIT_FAILURE;
    }
    printf("\n");

    printf("Actual Public Key:   ");
    if(fprintf_ec_point(stdout, test_wrapper->group, test_wrapper->point,
                        POINT_CONVERSION_COMPRESSED, NULL)) {
        fprintf(stderr, "ERROR: fprintf_point failed.\n");

        ec_test_wrapper_destroy(test_wrapper);

        return EXIT_FAILURE;
    }
    printf("\n");

    ec_test_wrapper_destroy(test_wrapper);

    return status;
}
