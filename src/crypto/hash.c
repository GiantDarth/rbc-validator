//
// Created by chaos on 2/28/2021.
//

#include "hash.h"

int evp_hash(unsigned char *digest, EVP_MD_CTX *ctx, const EVP_MD *md,
             const unsigned char *msg, size_t msg_size) {
    EVP_MD_CTX *new_ctx = NULL;

    if(msg == NULL) {
        return 1;
    }

    if(ctx == NULL) {
        if(md == NULL || (ctx = new_ctx = EVP_MD_CTX_new()) == NULL) {
            return 1;
        }
    }

    if(!EVP_DigestInit_ex(ctx, md, NULL)) {
        return 1;
    }

    if(!EVP_DigestUpdate(ctx, msg, msg_size)) {
        return 1;
    }

    if(!EVP_DigestFinal_ex(ctx, digest, NULL)) {
        return 1;
    }

    EVP_MD_CTX_free(new_ctx);

    return 0;
}

int evp_salt_hash(unsigned char *digest, EVP_MD_CTX *ctx, const EVP_MD *md,
                  const unsigned char *msg, size_t msg_size,
                  const unsigned char *salt, size_t salt_size) {
    EVP_MD_CTX *new_ctx = NULL;

    if(msg == NULL || salt == NULL) {
        return 1;
    }

    if(ctx == NULL) {
        if(md == NULL || (ctx = new_ctx = EVP_MD_CTX_new()) == NULL) {
            return 1;
        }
    }

    if(!EVP_DigestInit_ex(ctx, md, NULL)) {
        return 1;
    }

    if(!EVP_DigestUpdate(ctx, msg, msg_size)) {
        return 1;
    }

    if(!EVP_DigestUpdate(ctx, salt, salt_size)) {
        return 1;
    }

    if(!EVP_DigestFinal_ex(ctx, digest, NULL)) {
        return 1;
    }

    EVP_MD_CTX_free(new_ctx);

    return 0;
}