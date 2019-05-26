import secrets
import random
import uuid
import subprocess
import re

from scipy.special import comb
from Crypto.Cipher import AES
from bitarray import bitarray

KEY_SIZE = 32
ITERATIONS = 100
TIMEOUT = 10


def decode_ordinal(ordinal, mismatches, key_size):
    perm = 0
    for bit in range(key_size * 8 - 1, 0, -1):
        binomial = comb(bit, mismatches, exact=True)
        if ordinal >= binomial:
            ordinal -= binomial
            perm |= 0b1 << bit
            mismatches -= 1

    return perm


def get_corrupted_key(key, mismatches):
    binomial = comb(len(key) * 8, mismatches, exact=True)
    ordinal = random.randrange(binomial)

    perm = decode_ordinal(ordinal, mismatches, KEY_SIZE)
    perm_bits = bitarray()
    perm_bits.frombytes(perm.to_bytes(length=KEY_SIZE, byteorder="big"))

    key_bits = bitarray()
    key_bits.frombytes(key)

    corrupted_key_bits = key_bits ^ perm_bits

    return corrupted_key_bits.tobytes()


def do_run(mismatches: int, subkey_size: int):
    user_id = uuid.uuid4()
    key = secrets.token_bytes(KEY_SIZE)
    corrupted_key = get_corrupted_key(key, mismatches)

    server_subkeys = [bytearray(key[index:index + subkey_size]) for index in range(0, KEY_SIZE, subkey_size)]
    client_subkeys = [bytearray(corrupted_key[index:index + subkey_size]) for index in range(0, KEY_SIZE, subkey_size)]
    ciphers = []

    for server_subkey, client_subkey in zip(server_subkeys, client_subkeys):
        nonce = secrets.token_bytes(KEY_SIZE - subkey_size)

        server_subkey.extend(nonce)
        client_subkey.extend(nonce)

        aes = AES.new(client_subkey, AES.MODE_ECB)
        ciphers.append(aes.encrypt(user_id.bytes))

    duration = 0

    for subkey, cipher in zip(server_subkeys, ciphers):
        # Call hamming_validator over wsl with the UUID, the full server subkey, the client cipher, and only the
        # necessary subkey size set
        # Only extract the stderr output in verbose mode to get the actual time taken searching in text mode, and
        # make sure to check if the return code was zero or not
        try:
            validator_proc = subprocess.run(["hamming_validator", "-v", "-s", str(subkey_size * 8),
                                             str(user_id), subkey.hex(), cipher.hex()],
                                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                            universal_newlines=True, check=True, timeout=TIMEOUT)
        except subprocess.TimeoutExpired:
            return float('inf')

        # Get the first line such that "Clock" is contained within it.
        line = next(line for line in validator_proc.stderr.split('\n') if re.search(r'Clock', line))
        # Get only the decimal output (in seconds) and increment duration by its value
        duration += float(line.split(' ')[3])

    return duration


if __name__ == "__main__":
    print("Mismatches,1,2,4,8,16,32")

    for mismatches in range(KEY_SIZE * 8 + 1):
        print(mismatches, end=",", flush=True)

        values = []

        for subkey_count in [1, 2, 4, 8, 16, 32]:
            subkey_size = KEY_SIZE // subkey_count

            total = 0
            # Print out the average time taken out of ITERATION number of runs
            for _ in range(ITERATIONS):
                total += do_run(mismatches, subkey_size)
                if total == float('inf'):
                    break

            print(total / ITERATIONS, end="")
            values.append(total / ITERATIONS)

            if subkey_count < 32:
                print(",", end="", flush=True)
            else:
                print(flush=True)

        if all(value == float('inf') for value in values):
            break
