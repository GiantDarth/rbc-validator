#!/usr/bin/env bash

mpirun ./rbc_validator_mpi --mode=aes -rv -m3
mpirun ./rbc_validator_mpi --mode=aes -bv -m3
[[ $(mpirun ./rbc_validator_mpi --mode=aes -v -m3 \
    ddca0139c56a104940ecb16c9a64c689d18fa36c7d6bab71563dd0e540bdd028 \
    73962ffac2a737632b4e3dc0ce424dac \
    78df66c7-4723-434f-b5b9-ae61e02cd97c) == \
  "ddca0139c56a104940ecb16c9a64c689d18fa36c7d63aa71543dd0e540bdd028" ]]