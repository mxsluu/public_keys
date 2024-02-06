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

alices_keys = public_private_key_generation(q, a)
bobs_keys = public_private_key_generation(q, a)
alices_secret = key_generation(bobs_keys[0], alices_keys[1], q)
bobs_secret = key_generation(alices_keys[0], bobs_keys[1], q)
print("The shared secret should be: Alice's", alices_secret, "Bob's", bobs_secret)

print("\nMallory intercepts and tampers with Alice's public key and Bob's public key.")
print("Mallory uses her own public key to send back to Alice and Bob to impersonate them.")
mallorys_keys = public_private_key_generation(q, a)

mallorys_secret_with_alice = key_generation(alices_keys[0], mallorys_keys[1], q)
alices_secret_with_mallory = key_generation(mallorys_keys[0], alices_keys[1], q)
print("Alice and Malloy now shares the following secret: Alice's", alices_secret_with_mallory, "Mallory's", mallorys_secret_with_alice)

mallorys_secret_with_bobs = key_generation(bobs_keys[0], mallorys_keys[1], q)
bobs_secret_with_mallory = key_generation(mallorys_keys[0], bobs_keys[1], q)
print("Bob and Malloy now shares the following secret: Bob's", bobs_secret_with_mallory, "Mallory's", mallorys_secret_with_bobs)


alices_msg = pad(b"Hi Bob!", 16)
bobs_msg = pad(b"Hi Alice!", 16)
mallorys_message_to_bob = pad(b"Hey Bob, it's Alice. Can you send me $10? I'll pay you back tomorrow.", 16)
mallorys_message_to_alice = pad(b"Hey Alice, it's Bob. Can you send me $10? I'll pay you back tomorrow.", 16)

print("\nAlice's intended message to Bob is:", alices_msg)
print("Bob's intended message to Alice is:", bobs_msg)
print("Mallory's modifies Alice's message to Bob to be:", mallorys_message_to_bob)
print("Mallory's modifies Bob's message to Alice to be:", mallorys_message_to_alice)

iv = token_bytes(16)
k = bytes(alices_secret, 'utf-8')

cipher_mallory_alice = AES.new(k, AES.MODE_CBC, iv)
cipher_mallory_bob = AES.new(k, AES.MODE_CBC, iv)
cipher_alice_bob = AES.new(k, AES.MODE_CBC, iv)
cipher_bob_alice = AES.new(k, AES.MODE_CBC, iv)

mallory_to_bob_ciphertext = cipher_mallory_alice.encrypt(mallorys_message_to_bob)
mallory_to_alice_ciphertext = cipher_mallory_bob.encrypt(mallorys_message_to_alice)
intercepted_alice_bob = cipher_alice_bob.encrypt(alices_msg)
intercepted_bob_alice = cipher_bob_alice.encrypt(bobs_msg)

print("\nAlice sends the ciphertext to Mallory thinking it is Bob:", intercepted_alice_bob)
print("Bob sends the ciphertext to Mallory thinking it is Alice:", intercepted_bob_alice)
print("\nMallory sends Alice the cipher text impersonating Bob:", mallory_to_alice_ciphertext)
print("Mallory sends Bob the cipher text impersonating Alice:", mallory_to_bob_ciphertext)


decipher_alice = AES.new(k, AES.MODE_CBC, iv)
decipher_bob = AES.new(k, AES.MODE_CBC, iv)
alice_plaintext = unpad(decipher_alice.decrypt(mallory_to_alice_ciphertext), 16)
bob_plaintext = unpad(decipher_bob.decrypt(mallory_to_bob_ciphertext), 16)

print("\nAlice receives Mallory's ciphertext and decrypts it to:", alice_plaintext.decode())
print("Bob receives Mallory's ciphertext and decrypts it to:", bob_plaintext.decode())