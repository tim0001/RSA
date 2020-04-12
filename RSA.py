# An implementation of RSA for demonstration purpose only

from secrets import randbits
from math import gcd, floor, ceil

# converts string to an integer
def str2num (message) :
    b = bytes(message, 'utf-8')
    return int.from_bytes(b, 'big', signed=False)


# converts int to string
def num2str (num) :
    b = num.to_bytes(ceil(num.bit_length() / 8), 'big', signed=False)
    return b.decode("utf-8")

# Extended Euclidean Algorithm
# returns (gcd(a,b), x, y) where
# a*x + b*y = gcd(a,b)
def egcd (a, b) :
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = egcd(b % a, a)
        return g, x - (b // a) * y, y


# Modular inverse of a (mod m)
def modinv (a, m) :
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m


# Fermat primality test with 2 as witness
def probPrime (p) :
    return pow(2, p-1, p) == 1


# Generate random prime of size bits
# uses operating system's random number generator
# which may or may not be secure
def randPrime (bits) :
    while (True) :
        p = randbits(bits)
        p |= (3 << (bits-2))  # set top 2 bits to 1 to ensure p*p gives int of size 2*bits
        if probPrime(p) : return p


# Euler's totient for n with prime factors p and q
def phi (p, q) :
    return (p-1)*(q-1)


# Generate RSA keys (e, d, n, p, q) where n has size bitsize
def genKeys (bitsize) :
    e = 65537  # set e constant for quick encryption
    pbits = ceil(bitsize / 2)
    qbits = floor(bitsize / 2)
    gap = pbits - 100  # |p - q| should be > 2^gap to prevent easy factoring
    p = randPrime(pbits)
    q = randPrime(qbits)

    while gcd(e, phi(p, q)) != 1 or abs(p-q) >> gap == 0:
        p = randPrime(pbits)
        q = randPrime(qbits)

    return e, modinv(e, phi(p, q)), p*q, p, q


# Encrypt message with RSA public key (e, n)
# Warning: messages are not padded!
def encrypt (message, e, n) :
    return pow(str2num(message), e, n)


# Decrypt cipher with RSA private key (d, n)
# takes cipher in the form of int
def decrypt (num, d, n) :
    return num2str(pow(num, d, n))


if __name__ == "__main__":
    e, d, n, p, q = genKeys(1024)
    m = "hello world"
    c = encrypt(m, e, n)
    print("e:", e)
    print("d:", d)
    print("n:", n)
    print("message:", m)
    print("encrypted message:", c)
    print("decrypted message:", decrypt(c, d, n))
