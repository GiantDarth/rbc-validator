#!/usr/bin/env bash

set -x

./rbc_validator --mode=aes -rv -m3
./rbc_validator --mode=aes -bv -m3

[[ $(./rbc_validator --mode=aes -v -m3 \
    ddca0139c56a104940ecb16c9a64c689d18fa36c7d6bab71563dd0e540bdd028 \
    73962ffac2a737632b4e3dc0ce424dac \
    78df66c7-4723-434f-b5b9-ae61e02cd97c) == \
  "ddca0139c56a104940ecb16c9a64c689d18fa36c7d63aa71543dd0e540bdd028" ]]

[[ $(./rbc_validator --mode=aes -rvca -m2 -t1 |& grep searched | cut -d' ' -f4) == 32897 ]]
[[ $(./rbc_validator --mode=aes -rvcaf -m2 -t1 |& grep searched | cut -d' ' -f4) == 32640 ]]

[[ $(./rbc_validator --mode=aes -rvca -m2 |& grep searched | cut -d' ' -f4) == 32897 ]]
[[ $(./rbc_validator --mode=aes -rvcaf -m2 |& grep searched | cut -d' ' -f4) == 32640 ]]
