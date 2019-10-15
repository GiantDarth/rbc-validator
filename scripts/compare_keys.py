import sys
import math

from bitarray import bitarray

ECC_CURVE = "secp256r1"


def choose(n, k):
    return math.factorial(n) // (math.factorial(k) * math.factorial(n - k))


def encode_ordinal(errors: bitarray):
    ordinal = 0
    bit_positions = list([index for index, bit in enumerate(errors) if bit])

    print(bit_positions)

    for index, bit_pos in enumerate(bit_positions, 1):
        print("{} choose {} = {}".format(bit_pos, index, choose(bit_pos, index)))
        ordinal += choose(bit_pos, index)

    return ordinal


if __name__ == "__main__":
    rank_count = int(sys.argv[1])

    first_key = bitarray(endian="little")
    first_key.frombytes(bytes.fromhex(sys.argv[2]))

    second_key = bitarray(endian="little")
    second_key.frombytes(bytes.fromhex(sys.argv[3]))

    errors = first_key ^ second_key
    ordinal = encode_ordinal(errors)
    binom = choose(errors.length(), errors.count())

    print("First Key: ", first_key.tobytes().hex())
    print("Second Key:", second_key.tobytes().hex())
    print("Difference:", errors.tobytes().hex())
    print("Difference Count:", errors.count())
    print("Combination Ordinal:", ordinal)
    print("Total Combinations:", binom)
    print("Rank Responsibility:", (ordinal * rank_count) // binom)
