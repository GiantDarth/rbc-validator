#!/usr/bin/env bash

set -x

./rbc_validator --mode=sha1 -rv -m2
./rbc_validator --mode=sha1 -bv -m2
[[ $(./rbc_validator --mode=sha1 -v -m2 \
    fe52583b332be98b6c4f5d0b612d694fe0f353d3e93ee3abe974d9896b1756a9 \
    a644c34228cf4be1088256674500c23f076e217a) == \
  "fe52503b332be98b6c4f5d0b212d694fe0f353d3e93ee3abe974d9896b1756a9" ]]
# w/ Salt
[[ $(./rbc_validator --mode=sha1 -v -m2 \
    4263b155af411d846fb58a5733b78c0fd3223589fdf5e092dea8dd90dda43687 \
    b190d1144744c286cb1c4ce35ca0fc10dc8a802d \
    a1502d6ab566ea4126663456c1080d2e) == \
  "4263b155af411d846fb58a5733b78c0fd3223589fdf5e092dea8dd10cda43687" ]]