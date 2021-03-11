#!/usr/bin/env bash

set -x

mpirun ./rbc_validator_mpi --mode=chacha20 -rv -m2
mpirun ./rbc_validator_mpi --mode=chacha20 -bv -m2
[[ $(./rbc_validator_mpi --mode=chacha20 -v -m3 \
    54b93e74f84544b592b1909f4f44386c20cea701d01d44da527f326b7893ea80 \
    185e5fde30cbc350b92f44ea7f93e9a9 \
    b3022319-3c3f-44d3-8023-ee6b540335a5 \
    0000000092e26c1446222ecd8d2fe2ac) == \
  "54b93e74f84544b592b1909f4f44386c20cea701d01d44da567f336b7893ea80" ]]