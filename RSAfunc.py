from Crypto.Util.number import getStrongPrime

def RSA():
    p = 0
    q = 0
    e = 65537
    while p == q:
        p = getStrongPrime(2048, e)
        q = getStrongPrime(2048, e)
    n = p * q
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    return [(e, n), (d, n)]
