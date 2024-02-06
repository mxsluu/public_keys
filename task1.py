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

alices_keys = public_private_key_generation(37, 5)
print(alices_keys[0])
bobs_keys = public_private_key_generation(q, a)

alices_secret = key_generation(bobs_keys[0], alices_keys[1], q)
bobs_secret = key_generation(alices_keys[0], bobs_keys[1], q)

print("The shared secret: Alice's", alices_secret, "Bob's", bobs_secret)

alices_msg = pad(b"Hi Bob! This is my encrypted message to you my friend :D !", 16)
bobs_msg = pad(b"Hi Alice! I got your message. That was pretty cool!", 16)

print("\nAlice's message to Bob is:", alices_msg)
print("Bob's message to Alice is:", bobs_msg)

iv = token_bytes(16)
k = bytes(alices_secret, 'utf-8')

cipher_alice = AES.new(k, AES.MODE_CBC, iv)
cipher_bob = AES.new(k, AES.MODE_CBC, iv)

alice_ciphertext = cipher_alice.encrypt(alices_msg)
bob_ciphertext = cipher_bob.encrypt(bobs_msg)

print("\nAlice sends the cipher text:", alice_ciphertext)
print("Bob sends the cipher text:", bob_ciphertext)

decipher_alice = AES.new(k, AES.MODE_CBC, iv)
decipher_bob = AES.new(k, AES.MODE_CBC, iv)
alice_plaintext = unpad(decipher_alice.decrypt(alice_ciphertext), 16)
bob_plaintext = unpad(decipher_bob.decrypt(bob_ciphertext), 16)

print("\nAlice receives Bob's ciphertext and decrypts it to:", bob_plaintext.decode())
print("Bob receives Alice's ciphertext and decrypts it to:", alice_plaintext.decode())