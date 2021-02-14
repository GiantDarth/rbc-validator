//
// Created by cp723 on 3/14/2019.
//

#ifndef RBC_AES256_NI_ENC_H
#define RBC_AES256_NI_ENC_H

#include <stddef.h>

/// Encrypts some message data using AES-256-ECB without padding
/// \param cipher The output encryption
/// \param key A pointer to at least 32 bytes of key data. Passing in a NULL pointer is undefined
/// behavior.
/// \param msg The message to be encrypted, designated to be msg_len bytes long.
/// \param msg_len Denotes the size of the message
/// \return Returns 0 on success or 1 on error.
int aes256_ecb_encrypt(unsigned char *cipher, const unsigned char *key, const unsigned char *msg,
                       size_t msg_len);

#endif // RBC_AES256_NI_ENC_H
