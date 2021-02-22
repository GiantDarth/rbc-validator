import sys
import secrets
import uuid

from Crypto.Cipher import AES

from util import corrupt_key

KEY_SIZE = 32

if __name__ == "__main__":
    mismatches = int(sys.argv[1])

    user_id = uuid.uuid4()
    key = secrets.token_bytes(KEY_SIZE)
    corrupted_key = corrupt_key(key, mismatches)

    aes = AES.new(corrupted_key, AES.MODE_ECB)
    cipher = aes.encrypt(user_id.bytes)

    print("UUID:", user_id)
    print("Key:", key.hex())
    print("Corrupted Key:", corrupted_key.hex())
    print("Cipher:", cipher.hex())
