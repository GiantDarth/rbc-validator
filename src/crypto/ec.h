//
// Created by chaos on 2/16/2021.
//

#ifndef RBC_VALIDATOR_CRYPTO_EC_H_
#define RBC_VALIDATOR_CRYPTO_EC_H_

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

int getEcPublicKey(EC_POINT* point, BN_CTX* ctx, const EC_GROUP* group,
                   const unsigned char* priv_key, size_t priv_key_size);
int fprintfEcPoint(FILE* stream, const EC_GROUP* group, const EC_POINT* point,
                   point_conversion_form_t form, BN_CTX* ctx);

#endif  // RBC_VALIDATOR_CRYPTO_EC_H_
