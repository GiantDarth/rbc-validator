//
// Created by chaos on 2/16/2021.
//

#include "ec.h"

#include <ctype.h>

#include <openssl/err.h>

void tolower_str(char *str);

void tolower_str(char *str) {
    if(str == NULL) {
        return;
    }

    for(int i = 0; str[i] != '\0'; i++){
        // Cast to unsigned char or else there is undefined behavior
        str[i] = (char)tolower((unsigned char)(str[i]));
    }
}

int get_ec_public_key(EC_POINT *point, BN_CTX *ctx, const EC_GROUP *group,
                      const unsigned char *priv_key, size_t priv_key_size) {
    BN_CTX *new_ctx = NULL;
    BIGNUM *scalar;

    if(ctx == NULL) {
        if((ctx = new_ctx = BN_CTX_secure_new()) == NULL) {
            return 1;
        }
    }

    BN_CTX_start(ctx);
    scalar = BN_CTX_get(ctx);

    if(scalar == NULL) {
        BN_CTX_end(ctx);
        BN_CTX_free(new_ctx);

        return 1;
    }

    BN_bin2bn(priv_key, priv_key_size, scalar);

    if(!EC_POINT_mul(group, point, scalar, NULL, NULL, NULL)) {
        BN_CTX_end(ctx);
        BN_CTX_free(new_ctx);

        return 1;
    }

    BN_CTX_end(ctx);
    BN_CTX_free(new_ctx);

    return 0;
}

int fprintf_ec_point(FILE *stream, const EC_GROUP *group, const EC_POINT *point,
                     point_conversion_form_t form, BN_CTX *ctx) {
    char *hex;

    if(group == NULL || point == NULL) {
        return 1;
    }

    if((hex = EC_POINT_point2hex(group, point, form, ctx)) == NULL) {
        fprintf(stderr, "ERROR: EC_POINT_point2hex failed.\nOpenSSL Error: %s\n",
                ERR_error_string(ERR_get_error(), NULL));

        return 1;
    }

    // Lowercase the hex since OpenSSL uses uppercase
    tolower_str(hex);
    fprintf(stream, "%s", hex);
    OPENSSL_free(hex);

    return 0;
}
