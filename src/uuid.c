//
// Created by chaos on 3/10/2021.
//

#include "uuid.h"

#include <string.h>

#include "util.h"

int uuid_parse(unsigned char* uuid, const char* uuid_str) {
    char c;
    int value;

    if (strnlen(uuid_str, UUID_STR_LEN) != UUID_STR_LEN) {
        return 1;
    }

    memset(uuid, 0, UUID_SIZE);

    for (size_t i = 0, j = 0; i < UUID_STR_LEN; i++) {
        c = uuid_str[i];

        if ((value = parse_hex_char(c)) >= 0) {
            value &= 0x0f;
            if (j % 2 == 0) {
                value <<= 4;
            }
            uuid[j++ / 2] |= value;
        }
        // If character is not dash, or if it is and is in the wrong place
        else if (c != '-' || (i != 8 && i != 13 && i != 18 && i != 23)) {
            // Malformed character
            return 1;
        }
    }

    return 0;
}

void uuid_unparse(char* uuid_str, const unsigned char* uuid) {
    size_t s = 0;

    for (size_t i = 0; i < UUID_SIZE; i++) {
        uuid_str[s++] = unparse_hex_char((uuid[i] >> 4) & 0x0f, 1);
        if (s == 8 || s == 13 || s == 18 || s == 23) {
            uuid_str[s++] = '-';
        }

        uuid_str[s++] = unparse_hex_char(uuid[i] & 0x0f, 1);
        if (s == 8 || s == 13 || s == 18 || s == 23) {
            uuid_str[s++] = '-';
        }
    }

    uuid_str[s] = '\0';
}