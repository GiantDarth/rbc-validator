//
// Created by chaos on 2/28/2021.
//

#include "hash.h"

#include <XKCP/KangarooTwelve.h>
#include <XKCP/KeccakHash.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

int keccakHash(unsigned char* digest, const size_t* digest_size, Keccak_HashInstance* inst,
               const unsigned char* msg, size_t msg_size, const unsigned char* salt,
               size_t salt_size);

int evpHash(unsigned char* digest, const size_t* digest_size, EVP_MD_CTX* ctx, const EVP_MD* md,
            const unsigned char* msg, size_t msg_size, const unsigned char* salt,
            size_t salt_size) {
    EVP_MD_CTX* new_ctx = NULL;

    if (msg == NULL) {
        return 1;
    }

    if (ctx == NULL) {
        if (md == NULL || (ctx = new_ctx = EVP_MD_CTX_new()) == NULL) {
            return 1;
        }
    }

    if (!EVP_DigestInit_ex(ctx, md, NULL)) {
        return 1;
    }

    if (!EVP_DigestUpdate(ctx, msg, msg_size)) {
        return 1;
    }

    if (salt != NULL && !EVP_DigestUpdate(ctx, salt, salt_size)) {
        return 1;
    }

    if (digest_size == NULL) {
        if (!EVP_DigestFinal_ex(ctx, digest, NULL)) {
            return 1;
        }
    } else {
        if (!EVP_DigestFinalXOF(ctx, digest, *digest_size)) {
            return 1;
        }
    }

    EVP_MD_CTX_free(new_ctx);

    return 0;
}

int md5Hash(unsigned char* digest, const unsigned char* msg, size_t msg_size,
            const unsigned char* salt, size_t salt_size) {
    MD5_CTX ctx;

    if (!MD5_Init(&ctx)) {
        return 1;
    }

    if (!MD5_Update(&ctx, msg, msg_size)) {
        OPENSSL_cleanse(&ctx, sizeof(ctx));
        return 1;
    }

    if (salt != NULL && !MD5_Update(&ctx, salt, salt_size)) {
        OPENSSL_cleanse(&ctx, sizeof(ctx));
        return 1;
    }

    if (!MD5_Final(digest, &ctx)) {
        OPENSSL_cleanse(&ctx, sizeof(ctx));
        return 1;
    }

    OPENSSL_cleanse(&ctx, sizeof(ctx));

    return 0;
}

int sha1Hash(unsigned char* digest, const unsigned char* msg, size_t msg_size,
             const unsigned char* salt, size_t salt_size) {
    SHA_CTX ctx;

    if (!SHA1_Init(&ctx)) {
        return 1;
    }

    if (!SHA1_Update(&ctx, msg, msg_size)) {
        OPENSSL_cleanse(&ctx, sizeof(ctx));
        return 1;
    }

    if (salt != NULL && !SHA1_Update(&ctx, salt, salt_size)) {
        OPENSSL_cleanse(&ctx, sizeof(ctx));
        return 1;
    }

    if (!SHA1_Final(digest, &ctx)) {
        OPENSSL_cleanse(&ctx, sizeof(ctx));
        return 1;
    }

    OPENSSL_cleanse(&ctx, sizeof(ctx));

    return 0;
}

int sha224Hash(unsigned char* digest, const unsigned char* msg, size_t msg_size,
               const unsigned char* salt, size_t salt_size) {
    SHA256_CTX ctx;

    if (!SHA224_Init(&ctx)) {
        return 1;
    }

    if (!SHA224_Update(&ctx, msg, msg_size)) {
        OPENSSL_cleanse(&ctx, sizeof(ctx));
        return 1;
    }

    if (salt != NULL && !SHA224_Update(&ctx, salt, salt_size)) {
        OPENSSL_cleanse(&ctx, sizeof(ctx));
        return 1;
    }

    if (!SHA224_Final(digest, &ctx)) {
        OPENSSL_cleanse(&ctx, sizeof(ctx));
        return 1;
    }

    OPENSSL_cleanse(&ctx, sizeof(ctx));

    return 0;
}

int sha256Hash(unsigned char* digest, const unsigned char* msg, size_t msg_size,
               const unsigned char* salt, size_t salt_size) {
    SHA256_CTX ctx;

    if (!SHA256_Init(&ctx)) {
        return 1;
    }

    if (!SHA256_Update(&ctx, msg, msg_size)) {
        OPENSSL_cleanse(&ctx, sizeof(ctx));
        return 1;
    }

    if (salt != NULL && !SHA256_Update(&ctx, salt, salt_size)) {
        OPENSSL_cleanse(&ctx, sizeof(ctx));
        return 1;
    }

    if (!SHA256_Final(digest, &ctx)) {
        OPENSSL_cleanse(&ctx, sizeof(ctx));
        return 1;
    }

    OPENSSL_cleanse(&ctx, sizeof(ctx));

    return 0;
}

int sha384Hash(unsigned char* digest, const unsigned char* msg, size_t msg_size,
               const unsigned char* salt, size_t salt_size) {
    SHA512_CTX ctx;

    if (!SHA384_Init(&ctx)) {
        return 1;
    }

    if (!SHA384_Update(&ctx, msg, msg_size)) {
        OPENSSL_cleanse(&ctx, sizeof(ctx));
        return 1;
    }

    if (salt != NULL && !SHA384_Update(&ctx, salt, salt_size)) {
        OPENSSL_cleanse(&ctx, sizeof(ctx));
        return 1;
    }

    if (!SHA384_Final(digest, &ctx)) {
        OPENSSL_cleanse(&ctx, sizeof(ctx));
        return 1;
    }

    OPENSSL_cleanse(&ctx, sizeof(ctx));

    return 0;
}

int sha512Hash(unsigned char* digest, const unsigned char* msg, size_t msg_size,
               const unsigned char* salt, size_t salt_size) {
    SHA512_CTX ctx;

    if (!SHA512_Init(&ctx)) {
        return 1;
    }

    if (!SHA512_Update(&ctx, msg, msg_size)) {
        OPENSSL_cleanse(&ctx, sizeof(ctx));
        return 1;
    }

    if (salt != NULL && !SHA512_Update(&ctx, salt, salt_size)) {
        OPENSSL_cleanse(&ctx, sizeof(ctx));
        return 1;
    }

    if (!SHA512_Final(digest, &ctx)) {
        OPENSSL_cleanse(&ctx, sizeof(ctx));
        return 1;
    }

    OPENSSL_cleanse(&ctx, sizeof(ctx));

    return 0;
}

int sha3224Hash(unsigned char* digest, const unsigned char* msg, size_t msg_size,
                const unsigned char* salt, size_t salt_size) {
    Keccak_HashInstance inst;

    if (Keccak_HashInitialize_SHA3_224(&inst) == KECCAK_FAIL) {
        return 1;
    }

    return keccakHash(digest, NULL, &inst, msg, msg_size, salt, salt_size);
}

int sha3_256Hash(unsigned char* digest, const unsigned char* msg, size_t msg_size,
                 const unsigned char* salt, size_t salt_size) {
    Keccak_HashInstance inst;

    if (Keccak_HashInitialize_SHA3_256(&inst) == KECCAK_FAIL) {
        return 1;
    }

    return keccakHash(digest, NULL, &inst, msg, msg_size, salt, salt_size);
}

int sha3_384Hash(unsigned char* digest, const unsigned char* msg, size_t msg_size,
                 const unsigned char* salt, size_t salt_size) {
    Keccak_HashInstance inst;

    if (Keccak_HashInitialize_SHA3_384(&inst) == KECCAK_FAIL) {
        return 1;
    }

    return keccakHash(digest, NULL, &inst, msg, msg_size, salt, salt_size);
}

int sha3_512Hash(unsigned char* digest, const unsigned char* msg, size_t msg_size,
                 const unsigned char* salt, size_t salt_size) {
    Keccak_HashInstance inst;

    if (Keccak_HashInitialize_SHA3_512(&inst) == KECCAK_FAIL) {
        return 1;
    }

    return keccakHash(digest, NULL, &inst, msg, msg_size, salt, salt_size);
}

int shake128Hash(unsigned char* digest, size_t digest_size, const unsigned char* msg,
                 size_t msg_size, const unsigned char* salt, size_t salt_size) {
    Keccak_HashInstance inst;

    if (Keccak_HashInitialize_SHAKE128(&inst) == KECCAK_FAIL) {
        return 1;
    }

    return keccakHash(digest, &digest_size, &inst, msg, msg_size, salt, salt_size);
}

int shake256Hash(unsigned char* digest, size_t digest_size, const unsigned char* msg,
                 size_t msg_size, const unsigned char* salt, size_t salt_size) {
    Keccak_HashInstance inst;

    if (Keccak_HashInitialize_SHAKE128(&inst) == KECCAK_FAIL) {
        return 1;
    }

    return keccakHash(digest, &digest_size, &inst, msg, msg_size, salt, salt_size);
}

int kang12Hash(unsigned char* digest, size_t digest_size, const unsigned char* msg, size_t msg_size,
               const unsigned char* salt, size_t salt_size) {
    KangarooTwelve_Instance inst;

    if (KangarooTwelve_Initialize(&inst, digest_size)) {
        return 1;
    }

    if (KangarooTwelve_Update(&inst, msg, msg_size)) {
        OPENSSL_cleanse(&inst, sizeof(inst));
        return 1;
    }

    if (salt != NULL && KangarooTwelve_Update(&inst, salt, salt_size)) {
        OPENSSL_cleanse(&inst, sizeof(inst));
        return 1;
    }

    if (KangarooTwelve_Final(&inst, digest, NULL, 0)) {
        OPENSSL_cleanse(&inst, sizeof(inst));
        return 1;
    }

    OPENSSL_cleanse(&inst, sizeof(inst));

    return 0;
}

int keccakHash(unsigned char* digest, const size_t* digest_size, Keccak_HashInstance* inst,
               const unsigned char* msg, size_t msg_size, const unsigned char* salt,
               size_t salt_size) {
    if (Keccak_HashUpdate(inst, msg, msg_size * 8) == KECCAK_FAIL) {
        OPENSSL_cleanse(inst, sizeof(*inst));
        return 1;
    }

    if (salt != NULL && Keccak_HashUpdate(inst, salt, salt_size * 8) == KECCAK_FAIL) {
        OPENSSL_cleanse(inst, sizeof(*inst));
        return 1;
    }

    if (Keccak_HashFinal(inst, digest) == KECCAK_FAIL) {
        OPENSSL_cleanse(inst, sizeof(*inst));
        return 1;
    }

    // Perform an XOF
    if (digest_size != NULL && Keccak_HashSqueeze(inst, digest, *digest_size) == KECCAK_FAIL) {
        OPENSSL_cleanse(inst, sizeof(*inst));
        return 1;
    }

    OPENSSL_cleanse(inst, sizeof(*inst));

    return 0;
}
