import sys
import secrets
import math
import random
import uuid

from Crypto.Cipher import AES
from bitarray import bitarray

KEY_SIZE = 32


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


def get_corrupted_key(key, mismatches):
    binom = choose(len(key) * 8, mismatches)
    ordinal = random.randrange(binom)

    perm = decode_ordinal(ordinal, mismatches, KEY_SIZE)
    perm_bits = bitarray()
    perm_bits.frombytes(perm.to_bytes(length=KEY_SIZE, byteorder="big"))

    key_bits = bitarray()
    key_bits.frombytes(key)

    corrupted_key_bits = key_bits ^ perm_bits

    return corrupted_key_bits.tobytes()


if __name__ == "__main__":
    mismatches = int(sys.argv[1])

    user_id = uuid.uuid4()
    key = secrets.token_bytes(KEY_SIZE)
    corrupted_key = get_corrupted_key(key, mismatches)

    aes = AES.new(corrupted_key, AES.MODE_ECB)
    cipher = aes.encrypt(user_id.bytes)

    print("UUID:", user_id)
    print("Key:", key.hex())
    print("Corrupted Key:", corrupted_key.hex())
    print("Cipher:", cipher.hex())
