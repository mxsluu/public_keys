from RSAfunc import *
from hashlib import sha256
from Crypto.Cipher import AES
from secrets import token_bytes
from Crypto.Util.Padding import pad, unpad

import random
def main():
    print("Generating RSA key....")
    keys = RSA()
    s = random.randint(0, keys[0][1])
    print("s is:", s)
    if s >= keys[0][1]:
        print("Plaintext is too large!")
        return None
    c = pow(s, keys[0][0], keys[0][1])

    print("c is:", c)
    print("Mallory takes the ciphertext and modifies it, forcing s to be something they know (s = 0)")
    s = b'0'

    alice_key = bytes(sha256(s).hexdigest()[0:16], 'utf-8')
    alice_message = b"Hi Bob!"
    print("Alice's message to Bob:", alice_message)
    iv = token_bytes(16)
    cipher_alice = AES.new(alice_key, AES.MODE_CBC, iv)
    encrypted_text = cipher_alice.encrypt(pad(alice_message, 16))
    print("Alice's encrypted message is", encrypted_text)

    print("Mallory knows s and can generate the key. They can now decrypt the message as well.")
    mallory_key = bytes(sha256(s).hexdigest()[0:16], 'utf-8')
    decipher_mallory = AES.new(mallory_key, AES.MODE_CBC, iv)
    decrypted_text = decipher_mallory.decrypt(encrypted_text)
    print("Mallory decrypts Alice's ciphertext to:", unpad(decrypted_text, 16))

if __name__ == "__main__":
    main()