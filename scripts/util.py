import math
import random
from typing import ByteString

from bitarray import bitarray
from Crypto.PublicKey.ECC import EccKey


def decode_ordinal(ordinal: int, mismatches: int, bits_len: int) -> bitarray:
    perm = bitarray(bits_len)
    perm.setall(False)

    bit = bits_len - 1
    while mismatches > 0:
        binom = math.comb(bit, mismatches)
        if ordinal >= binom:
            ordinal -= binom
            perm[bit] = True
            mismatches -= 1

        bit -= 1

    return perm


def encode_ordinal(errors: bitarray):
    ordinal = 0
    bit_positions = list([index for index, bit in enumerate(errors) if bit])

    print(bit_positions)

    for index, bit_pos in enumerate(bit_positions, 1):
        print("{} choose {} = {}".format(bit_pos, index, math.comb(bit_pos, index)))
        ordinal += math.comb(bit_pos, index)

    return ordinal


def corrupt_key(key: ByteString, mismatches: int) -> bytes:
    binom = math.comb(len(key) * 8, mismatches)
    ordinal = random.randrange(binom)

    perm = decode_ordinal(ordinal, mismatches, len(key) * 8)

    key_bits = bitarray()
    key_bits.frombytes(key)

    corrupted_key_bits = key_bits ^ perm

    return corrupted_key_bits.tobytes()


def get_ec_private_key_bytes(key: EccKey) -> bytes:
    assert key.has_private()

    modulus_bytes = key.pointQ.size_in_bytes()

    return key.d.to_bytes(modulus_bytes, "big")


def get_ec_public_key_bytes(key: EccKey, compress) -> bytes:
    modulus_bytes = key.pointQ.size_in_bytes()

    if compress:
        y_byte = 2 + key.pointQ.y.is_odd()

        return bytes([y_byte]) + key.pointQ.x.to_bytes(modulus_bytes, "big")
    else:
        return key.pointQ.x.to_bytes(modulus_bytes, "big") + key.pointQ.y.to_bytes(modulus_bytes, "big")