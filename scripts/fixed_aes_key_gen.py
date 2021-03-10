import sys
import secrets
import uuid

from Crypto.Cipher import AES

from config import AES_KEY_SIZE
from util import corrupt_key


if __name__ == "__main__":
    mismatches = int(sys.argv[1])

    user_id = uuid.uuid4()
    key = secrets.token_bytes(AES_KEY_SIZE)
    corrupted_key = corrupt_key(key, mismatches)

    aes = AES.new(corrupted_key, AES.MODE_ECB)
    cipher = aes.encrypt(user_id.bytes)

    print("Key:", key.hex())
    print("Corrupted Key:", corrupted_key.hex())
    print("Cipher:", cipher.hex())
    print("UUID:", user_id)
