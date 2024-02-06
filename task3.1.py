from RSAfunc import *

def main():
    print("Generating RSA key....")
    alice_keys = RSA()
    bobs_message = b"Hello Alice!"
    print("Alice sends Bob her public key.")
    print("Bob's message to Alice is:", bobs_message)

    plaintext_bob = int(bobs_message.hex(), 16)
    if plaintext_bob >= alice_keys[0][1]:
        print("Plaintext is too large!")
        return None
    print("Encrypting message and generating ciphertext using Alice's public key.")

    ciphertext = pow(plaintext_bob, alice_keys[0][0], alice_keys[0][1])
    print("Bob sends the ciphertext to Alice:", ciphertext)
    pt = pow(ciphertext, alice_keys[1][0], alice_keys[1][1])
    pt = bytes.fromhex(hex(pt)[2:]).decode('utf-8')
    print("Alice decrypts the ciphertext using her private key:", pt)
if __name__ == "__main__":
    main()