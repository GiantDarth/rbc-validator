./rbc_validator_mpi --usage
./rbc_validator_mpi --help

mpirun ./rbc_validator_mpi --mode=aes -rv -m3
mpirun ./rbc_validator_mpi --mode=aes -bv -m3
[[ $(mpirun ./rbc_validator_mpi --mode=aes -v -m3 \
    ddca0139c56a104940ecb16c9a64c689d18fa36c7d6bab71563dd0e540bdd028 \
    73962ffac2a737632b4e3dc0ce424dac \
    78df66c7-4723-434f-b5b9-ae61e02cd97c) == \
  "ddca0139c56a104940ecb16c9a64c689d18fa36c7d63aa71543dd0e540bdd028" ]]

mpirun ./rbc_validator_mpi --mode=ecc -rv -m2
mpirun ./rbc_validator_mpi --mode=ecc -bv -m2
# Compressed Form
[[ $(mpirun ./rbc_validator_mpi --mode=ecc -v -m2 \
    000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
    02d253229db92099808ace5668aa3c1b182a3857ebacbee5e67eeb0f5e422a1ce9) == \
   "100102030405060718090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" ]]
# Uncompressed Form
[[ $(mpirun ./rbc_validator_mpi --mode=ecc -v -m2 \
    000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
    04d253229db92099808ace5668aa3c1b182a3857ebacbee5e67eeb0f5e422a1ce90f1f52b9ba6ea8242d469c6208f8ba304056181a85406542bf3a89b5badb1cee) == \
   "100102030405060718090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" ]]
# Hybrid Form
[[ $(mpirun ./rbc_validator_mpi --mode=ecc -v -m2 \
    000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
    06d253229db92099808ace5668aa3c1b182a3857ebacbee5e67eeb0f5e422a1ce90f1f52b9ba6ea8242d469c6208f8ba304056181a85406542bf3a89b5badb1cee) == \
   "100102030405060718090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" ]]