# Alexander Lee - ahl256
# Applied Cryptography and Network Security
# Spring 2022
# Assignment 09 - RSA Encryption Implementation

from random import randrange

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
