import secrets
import uuid
import subprocess
import re
import math

from Crypto.Cipher import AES

from config import AES_KEY_SIZE
from util import corrupt_key

ITERATIONS = 100
TIMEOUT = 10


def do_run(mismatches: int, key_size: int, subkey_size: int):
    user_id = uuid.uuid4()
    key = secrets.token_bytes(key_size)
    corrupted_key = corrupt_key(key, mismatches)

    server_subkeys = [bytearray(key[index:index + subkey_size])
                      for index in range(0, len(key), subkey_size)]
    client_subkeys = [bytearray(corrupted_key[index:index + subkey_size])
                      for index in range(0, len(corrupted_key), subkey_size)]
    ciphers = []

    for server_subkey, client_subkey in zip(server_subkeys, client_subkeys):
        nonce = secrets.token_bytes(len(key) - subkey_size)

        server_subkey.extend(nonce)
        client_subkey.extend(nonce)

        aes = AES.new(client_subkey, AES.MODE_ECB)
        ciphers.append(aes.encrypt(user_id.bytes))

    duration = 0

    for subkey, cipher in zip(server_subkeys, ciphers):
        # Call rbc_validator over wsl with the UUID, the full server subkey, the client cipher, and only
        # the necessary subkey size set
        # Only extract the stderr output in verbose mode to get the actual time taken searching in text
        # mode, and make sure to check if the return code was zero or not
        try:
            validator_proc = subprocess.run(["rbc_validator", "--mode=aes", "-v", "-s",
                                             str(subkey_size * 8), subkey.hex(), str(user_id),
                                             cipher.hex()],
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

    for mismatches in range(AES_KEY_SIZE * 8 + 1):
        print(mismatches, end=",", flush=True)

        values = []

        for subkey_count in [2 ** i for i in range(int(math.log2(AES_KEY_SIZE)) + 1)]:
            subkey_size = AES_KEY_SIZE // subkey_count

            total = 0
            # Print out the average time taken out of ITERATION number of runs
            for _ in range(ITERATIONS):
                total += do_run(mismatches, AES_KEY_SIZE, subkey_size)
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
