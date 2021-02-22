//
// Created by chaos on 2/16/2021.
//

#include "ec.h"

int set_ec_point(EC_POINT *p, BN_CTX *bn_ctx, const unsigned char *uncomp_pub_key,
                 const EC_GROUP *group) {
    BIGNUM *x, *y;

    BN_CTX_start(bn_ctx);

    x = BN_CTX_get(bn_ctx);
    y = BN_CTX_get(bn_ctx);

    // Check the last BN_CTX_get result for any errors
    if(y == NULL) {
        BN_CTX_end(bn_ctx);

        return 1;
    }

    if(BN_bin2bn(uncomp_pub_key, ECC_PUB_KEY_SIZE / 2, x) == NULL) {
        BN_CTX_end(bn_ctx);

        return 1;
    }

    if(BN_bin2bn(uncomp_pub_key + ECC_PUB_KEY_SIZE / 2, ECC_PUB_KEY_SIZE / 2, y) == NULL) {
        BN_CTX_end(bn_ctx);

        return 1;
    }

    if(!EC_POINT_set_affine_coordinates(group, p, x, y, NULL)) {
        BN_CTX_end(bn_ctx);

        return 1;
    }

    BN_CTX_end(bn_ctx);

    return 0;
}
