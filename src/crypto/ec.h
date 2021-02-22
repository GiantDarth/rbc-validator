//
// Created by chaos on 2/16/2021.
//

#ifndef HAMMING_BENCHMARK_EC_H
#define HAMMING_BENCHMARK_EC_H

#include <openssl/obj_mac.h>
#include <openssl/ec.h>

#define EC_CURVE NID_X9_62_prime256v1

#define EC_PRIV_KEY_SIZE 32
#define EC_PUB_COMP_KEY_SIZE 33
#define EC_PUB_UNCOMP_KEY_SIZE 65

int fprintf_ec_point(FILE *stream, const EC_GROUP *group, const EC_POINT *point,
                     point_conversion_form_t form, BN_CTX *ctx);

#endif //HAMMING_BENCHMARK_EC_H
