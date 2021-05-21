#!/usr/bin/env bash

set -x

./rbc_validator --mode=sha3-384 -rv -m2
./rbc_validator --mode=sha3-384 -bv -m2
[[ $(./rbc_validator --mode=sha3-384 -v -m2 \
    0421885f0af3559ab9cb78ef6dcb3d46d7debd834ad87e61b8773c8f24fe1817 \
    9d2d8df9bb57c2f5fb3bb3b0e96091e31eb08aa70ce66ee51492f83b9b1b0a1a3adf819789af2e0ea3dff5681fa4d87a) == \
  "0421895f0af3559ab9db78ef6dcb3d46d7debd834ad87e61b8773c8f24fe1817" ]]
# w/ Salt
[[ $(./rbc_validator --mode=sha3-384 -v -m2 \
    4c5d41d98af9b582d27206769cb5d35d6e870d742ac2e83774c45809aa1f5114 \
    8577b043f052dcfd9360d09033606c853705f23a8412e131861bc80b94b34fd898fe1a314f570fc2e349de435b80d6b0 \
    0beabe4beee3ca3a51762120df37fb35) == \
  "4c5d41d98af9b502d27206769cb5d35d6e870d742ac2e83774c45809aa9f5114" ]]