# Functions


from math import *
import sys
from time import time


class RSA:
    def __init__(self):
        x = 0

    def pow_mod_n(a, b, n):
        if b == 0:
            return 1
        elif b % 2 == 0:
            t = pow_mod_n(a, b // 2, n)
            return mult(t, t, n)
        else:
            return mult(a, pow_mod_n(a, b - 1, n), n)

    def lcm(a, b):
        return a * b // gcd(a, b)

    def rsa_encrypt(m, public_key):
        n, e = public_key
        return pow_mod_n(m, e, n)

    def rsa_decrypt(c, private_key):
        n, e = private_key
        return pow_mod_n(c, d, n)



# Multiplicative inverse given by Wikipedia article
# def inverse(a, n):
#    (t, new_t, r, new_r) = (0, 1, n, a)
#    while new_r != 0:
#        quotient = r // new_r
#        (t, new_t) = (new_t, t - quotient * new_t)
#        (r, new_r) = (new_r, r - quotient * new_r)
#    if r > 1:
#        return -1 # a is not invertible in Z/nZ
#    else:
#        return t % n


# My rewrite
def rinv_helper(r, new_r, t=0, new_t=1):
    if new_r > 0:
        quotient = r // new_r
        return rinv_helper(new_r, r % new_r, new_t, t - (r // new_r) * new_t)
    else:
        return t


def inverse(a, n):
    if gcd(a, n) == 1:
        return rinv_helper(n, a) % n
    else:
        return "a is not invertible in Z/nZ"


def string2int(s):
    return int.from_bytes(s.encode("utf-8"), byteorder="big")


def int2string(n):
    return (n.to_bytes(((n.bit_length() + 7) // 8), byteorder="big")).decode("utf-8")


def encrypt(plaintext_string, public_key):
    return int2string(rsa_encrypt(string2int(plaintext_string), public_key))


def decrypt(ciphertext_string, private_key):
    return int2string(rsa_decrypt(string2int(ciphertext_string), private_key))


# Function that measures running time of function f with input n
#
def rt(f, n):
    starttime = time()
    return ([f(n), time() - starttime])


# Computes average run time of f(n) over m trials.
def rt_average(f, n, m):
    rt_total = 0
    for i in range(m):
        rt_total += rt(f, n)[1]
    return rt_total / m