//
// Created by chaos on 2/25/2021.
//

#include "cipher.h"

int evp_encrypt(unsigned char* cipher, EVP_CIPHER_CTX* ctx, const EVP_CIPHER* evp_cipher,
                const unsigned char* key, const unsigned char* msg, size_t msg_size,
                const unsigned char* iv) {
    int outlen, tmplen;
    EVP_CIPHER_CTX* new_ctx = NULL;

    if (ctx == NULL) {
        if (evp_cipher == NULL || (ctx = new_ctx = EVP_CIPHER_CTX_new()) == NULL) {
            return 1;
        }
    }

    if (!EVP_EncryptInit_ex(ctx, evp_cipher, NULL, key, iv)) {
        // If new_ctx is NULL, nothing happens
        EVP_CIPHER_CTX_free(new_ctx);

        return 1;
    }

    // Only disable padding in first instance
    if (evp_cipher) {
        EVP_CIPHER_CTX_set_padding(ctx, 0);
    }

    if (!EVP_EncryptUpdate(ctx, cipher, &outlen, msg, msg_size)) {
        // If new_ctx is NULL, nothing happens
        EVP_CIPHER_CTX_free(new_ctx);

        return 1;
    }

    if (!EVP_EncryptFinal_ex(ctx, cipher + outlen, &tmplen)) {
        // If new_ctx is NULL, nothing happens
        EVP_CIPHER_CTX_free(new_ctx);

        return 1;
    }

    // If new_ctx is NULL, nothing happens
    EVP_CIPHER_CTX_free(new_ctx);

    return 0;
}
