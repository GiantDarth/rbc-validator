import sys

from bitarray import bitarray

from util import choose, encode_ordinal


if __name__ == "__main__":
    rank_count = int(sys.argv[1])

    first_seed = bitarray(endian="little")
    first_seed.frombytes(bytes.fromhex(sys.argv[2]))

    second_seed = bitarray(endian="little")
    second_seed.frombytes(bytes.fromhex(sys.argv[3]))

    errors = first_seed ^ second_seed
    ordinal = encode_ordinal(errors)
    binom = choose(errors.length(), errors.count())

    print("First Seed: ", first_seed.tobytes().hex())
    print("Second Seed:", second_seed.tobytes().hex())
    print("Difference:", errors.tobytes().hex())
    print("Difference Count:", errors.count())
    print("Combination Ordinal:", ordinal)
    print("Total Combinations:", binom)
    print("Rank Responsibility:", (ordinal * rank_count) // binom)
