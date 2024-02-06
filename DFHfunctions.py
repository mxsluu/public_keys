import random
import hashlib
def public_private_key_generation(q, a):
    private_key = random.randint(0, q - 1)
    public_key = pow(a, private_key, q)
    return public_key, private_key

def key_generation(public_key, my_private_key, q):
    secret = str(pow(public_key, my_private_key, q))
    key = hashlib.sha256(secret.encode('utf-8')).hexdigest()
    return key[0:16]

