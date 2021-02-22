//
// Created by chaos on 2/16/2021.
//

#ifndef HAMMING_BENCHMARK_EC_H
#define HAMMING_BENCHMARK_EC_H

#include <openssl/obj_mac.h>
#include <openssl/ec.h>

#define ECC_CURVE NID_X9_62_prime256v1

#define ECC_PRIV_KEY_SIZE 32
#define ECC_PUB_KEY_SIZE 64

int set_ec_point(EC_POINT *p, BN_CTX *bn_ctx, const unsigned char *uncomp_pub_key,
                 const EC_GROUP *group);

#endif //HAMMING_BENCHMARK_EC_H
