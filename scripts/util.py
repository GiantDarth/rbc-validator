import math
import random

from bitarray import bitarray
from Crypto.PublicKey.ECC import EccKey


def choose(n, k):
    return math.factorial(n) // (math.factorial(k) * math.factorial(n - k))


def decode_ordinal(ordinal, mismatches, key_size):
    perm = 0
    for bit in range(key_size * 8 - 1, 0, -1):
        binom = choose(bit, mismatches)
        if ordinal >= binom:
            ordinal -= binom
            perm |= 0b1 << bit
            mismatches -= 1

    return perm


def encode_ordinal(errors: bitarray):
    ordinal = 0
    bit_positions = list([index for index, bit in enumerate(errors) if bit])

    print(bit_positions)

    for index, bit_pos in enumerate(bit_positions, 1):
        print("{} choose {} = {}".format(bit_pos, index, choose(bit_pos, index)))
        ordinal += choose(bit_pos, index)

    return ordinal


def corrupt_key(key, mismatches):
    binom = choose(len(key) * 8, mismatches)
    ordinal = random.randrange(binom)

    perm = decode_ordinal(ordinal, mismatches, len(key))
    perm_bits = bitarray()
    perm_bits.frombytes(perm.to_bytes(length=len(key), byteorder="big"))

    key_bits = bitarray()
    key_bits.frombytes(key)

    corrupted_key_bits = key_bits ^ perm_bits

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