# Alexander Lee - ahl256
# Applied Cryptography and Network Security
# Spring 2022
# Assignment 09 - RSA Encryption Implementation

# imports
from random import randrange

# constants
MIN_PRIME_SIZE = 1000000000
PRIME_RANGE = 1000000000000

# helper functions
def is_prime(n):
    """
    Primality test using trial division w/ 6k+/-1 optimization,
    per Wikipedia: https://en.wikipedia.org/wiki/Primality_test
    """
    if 2 <= n <= 3:
        return True
    if (n <= 1) or (n % 2 == 0) or (n % 3 == 0):
        return False
    i = 5
    stop = n ** 0.5
    while i <= stop:
        if (n % i == 0) or (n % (i+2) == 0):
            return False
        i += 6
    return True

def gen_random_prime(min_int, rng):
    """
    Generates a random prime that is at least min_int,\
    and at most min_int + rng.
    """
    while True:
        i = randrange(min_int, min_int+rng)
        if is_prime(i):
            return i

def gcd(x, y):
    """
    Finds greatest common divisor of x and y.
    """
    while (y != 0):
        temp = y
        y = x % y
        x = temp
    return x

def lcm(x, y):
    """
    Finds least common multiple using gcd function.
    """
    return (x*y)//gcd(x, y)

def get_e(c):
    """
    Finds a number coprime to c.
    """
    i = 2
    while i < c:
        if (c % i != 0):
            break
        i += 1
    return i

def mmi(n, m):
    """
    Finds modular multiplicative inverse of n (mod m).
    """
    return pow(n, -1, m)

def build_cryptosystem():
    """
    Builds RSA cryptosystem and returns keys.
    """
    # the cryptosystem
    p = gen_random_prime(MIN_PRIME_SIZE, PRIME_RANGE)
    q = gen_random_prime(MIN_PRIME_SIZE, PRIME_RANGE)
    n = p * q
    c = lcm(p-1, q-1)
    e = get_e(c)
    d = mmi(e, c)
    # keys
    pkey = (e, n)
    skey = (d, n)
    return (pkey, skey)

#==========================#
# Example execution of RSA #
#==========================#

print("\nRunning toy RSA demonstration:\n" + "="*30 + "\n")

# obtain keys; may need to try more than once if e is not invertible modulo c
print("Generating keys:")
keys = None
err = False
while True:
    try:
        keys = build_cryptosystem()
        break
    except(ValueError):
        print("Found non-invertible LCM; retrying")
        err = True
print("Completed key generation!\n")
pkey = keys[0]
skey = keys[1]

# use integer message for simplicity; encrypt and decrypt
M = 42
C = pow(M, pkey[0], pkey[1])
D = pow(C, skey[0], skey[1])

# illustrate results
print("Public key:\t\t({}, {})".format(pkey[0], pkey[1]))
print("Secret key:\t\t({}, {})".format(skey[0], skey[1]))
print("Message: \t\t{}\nCiphertext: \t\t{}\nDecrypted plaintext:\t{}".format(M, C, D))
