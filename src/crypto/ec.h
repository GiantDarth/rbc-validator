//
// Created by chaos on 2/16/2021.
//

#ifndef HAMMING_BENCHMARK_EC_H
#define HAMMING_BENCHMARK_EC_H

#include <openssl/obj_mac.h>
#include <openssl/ec.h>

int fprintf_ec_point(FILE *stream, const EC_GROUP *group, const EC_POINT *point,
                     point_conversion_form_t form, BN_CTX *ctx);

#endif //HAMMING_BENCHMARK_EC_H
