//
// Created by chaos on 3/10/2021.
//

#ifndef RBC_VALIDATOR_UUID_H
#define RBC_VALIDATOR_UUID_H

#define UUID_SIZE 16
#define UUID_STR_LEN 36

int uuid_parse(unsigned char *uuid, const char *uuid_str);
void uuid_unparse(char *uuid_str, const unsigned char *uuid);

#endif //RBC_VALIDATOR_UUID_H
