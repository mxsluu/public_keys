from DFHfunctions import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from secrets import token_bytes

q = int(
    "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371",
    16)
a = int(
    "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5",
    16)

a1 = 1  # public keys becomes 1, secret is 1
a2 = q  # public keys becomes 0, secret is 0
a3 = q - 1 # public keys becomes 1 or q - 1, secret is 1 or q - 1 both depends on what the private key is
possible_a = [a1, a2, a3]

for a in possible_a:
    print("-------------------------------------------------------------------------")
    print("Mallory tampers with the generator alpha setting a =", a)
    alices_keys = public_private_key_generation(q, a)
    bobs_keys = public_private_key_generation(q, a)
    mallorys_keys = public_private_key_generation(q, a)

    alices_secret = key_generation(bobs_keys[0], alices_keys[1], q)
    bobs_secret = key_generation(alices_keys[0], bobs_keys[1], q)

    print("The shared secret: Alice's", alices_secret, "Bob's", bobs_secret)

    if a == a3:
        secret1 = "1"
        secret2 = str(q - 1)
        potential_key1 = hashlib.sha256(secret1.encode('utf-8')).hexdigest()[0:16]
        potential_key2 = hashlib.sha256(secret2.encode('utf-8')).hexdigest()[0:16]
        print("Mallory narrows the potential shared keys down to 2 options:", potential_key1, "and", potential_key2)
    else:
        mallorys_alices_secret = key_generation(alices_keys[0], mallorys_keys[1], q)
        mallorys_bobs_secret = key_generation(bobs_keys[0], mallorys_keys[1], q)
        print("Mallory learns Alice's secret:", mallorys_alices_secret, "and Bob's secret:", mallorys_bobs_secret)


    alices_msg = pad(b"Hey Bob, the login for the website is 523, Don't tell anyone!", 16)
    bobs_msg = pad(b"Thanks Alice! The followup ID is 152. Please don't tell anyone.", 16)

    print("\nAlice's message to Bob is:", alices_msg)
    print("Bob's message to Alice is:", bobs_msg)

    iv = token_bytes(16)
    k = bytes(alices_secret, 'utf-8')
    if a == a3:
        mallorys_key_1 = bytes(potential_key1, 'utf-8')
        mallorys_key_2 = bytes(potential_key2, 'utf-8')
        decipher_mallory_alice_1 = AES.new(mallorys_key_1, AES.MODE_CBC, iv)
        decipher_mallory_alice_2 = AES.new(mallorys_key_2, AES.MODE_CBC, iv)
        decipher_mallory_bob_1 = AES.new(mallorys_key_1, AES.MODE_CBC, iv)
        decipher_mallory_bob_2 = AES.new(mallorys_key_2, AES.MODE_CBC, iv)

        mallory_alice_deciphers = [decipher_mallory_alice_1, decipher_mallory_alice_2]
        mallory_bob_deciphers = [decipher_mallory_bob_1, decipher_mallory_bob_2]
    else:
        mallorys_key = bytes(mallorys_alices_secret, 'utf-8')
        decipher_mallory_alice = AES.new(mallorys_key, AES.MODE_CBC, iv)
        decipher_mallory_bob = AES.new(mallorys_key, AES.MODE_CBC, iv)

    cipher_alice = AES.new(k, AES.MODE_CBC, iv)
    cipher_bob = AES.new(k, AES.MODE_CBC, iv)

    alice_ciphertext = cipher_alice.encrypt(alices_msg)
    bob_ciphertext = cipher_bob.encrypt(bobs_msg)

    print("\nAlice sends the cipher text:", alice_ciphertext)
    print("Bob sends the cipher text:", bob_ciphertext)

    if a == a3:
        for alice_decipher in mallory_alice_deciphers:
            try:
                alice_plaintext = unpad(alice_decipher.decrypt(alice_ciphertext), 16)
            except ValueError:
                print("\nWrong key for Alice was tried. Garbage:", alice_decipher.decrypt(alice_ciphertext))
        for bob_decipher in mallory_bob_deciphers:
            try:
                bob_plaintext = unpad(bob_decipher.decrypt(bob_ciphertext), 16)
            except ValueError:
                print("Wrong key for Bob was tried. Garbage:", bob_decipher.decrypt(bob_ciphertext))

        print("\nMallory intercepts Alice's ciphertext and decodes it to:", alice_plaintext)
        print("Mallory intercepts Bob's ciphertext and decodes it:", bob_plaintext)
    else:
        alice_plaintext = unpad(decipher_mallory_alice.decrypt(alice_ciphertext), 16)
        bob_plaintext = unpad(decipher_mallory_bob.decrypt(bob_ciphertext), 16)
        print("\nMallory intercepts Alice's message and decodes it:", alice_plaintext)
        print("Mallory intercepts Bob's message and decodes it:", bob_plaintext)




