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
