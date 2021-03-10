import sys
import secrets
import uuid

from Crypto.Cipher import ChaCha20

from util import corrupt_key

OPENSSL_NONCE_SIZE = 16
NONCE_SIZE = 12

if __name__ == "__main__":
    mismatches = int(sys.argv[1])

    user_id = uuid.uuid4()
    key = secrets.token_bytes(ChaCha20.key_size)
    corrupted_key = corrupt_key(key, mismatches)
    nonce = secrets.token_bytes(NONCE_SIZE)
    
    chacha20 = ChaCha20.new(key=corrupted_key, nonce=nonce)
    cipher = chacha20.encrypt(user_id.bytes)
    iv = chacha20.nonce

    print("Key:", key.hex())
    print("Corrupted Key:", corrupted_key.hex())
    print("Cipher:", cipher.hex())
    print("UUID:", user_id)
    print("IV:", (bytes(OPENSSL_NONCE_SIZE - len(iv)) + iv).hex())
