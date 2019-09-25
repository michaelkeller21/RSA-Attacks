from math import gcd
from Crypto.Util import number
from inverse import rec_inverse
from random import randrange

def lcm(a, b):
    return a * b // gcd(a, b)

def string2int(s):
    # return int.from_bytes(s.encode("utf-8"), byteorder = "big")
    return number.bytes_to_long(s.encode("utf-8"))


def int2string(n):
    # return (n.to_bytes(((n.bit_length() + 7) //8), byteorder = "big")).decode("utf-8")
    return number.long_to_bytes(n)

# --------------------------------------------------
# Faster decryption using the Chinese Remainder Theorem (CRT)
#
# Map an element a of Z_n* to an element of Z_p* x Z_q*
def Zn_to_ZpxZq(a, p, q):
    return ((a % p, a % q))


# Map an element (a, b) of Z_p* x Z_q* to Z_n*
def ZpxZq_to_Zn(a, p, b, q, n):
    s = rec_inverse(p, q)
    t = rec_inverse(q, p)

    # s is the inverse of p in Z_q*. It means sp = 1 (mod q).
    # Obviously sp = 0 (mod p). So sp in Z_n* maps to (0, 1) in Z_p* x Z_q*.
    # Similarly, The isomorphism maps tq in Z_n* to (1, 0) in Z_p* x Z_q*.

    # Therefore, spb = b (mod q) and (obviously) spb = 0 (mod p).
    # So spb in Z_n* maps to (0, b) in Z_p* x Z_q*. Similarly, the isomorphism
    # maps tqa in Z_n* to (a, 0) in Z_p* x Z_q*.

    # Combining the two, we get that spb + tqa = a (mod p) = b (mod q).
    # That is, the isomorphism maps spb + tqa in Z_n* to (a, b) in Z_p* x Z_q*.

    return ((s * p * b + t * q * a) % n)

# For the random fault attack described in section 5.2, the attacker needs
# to corrupt the contents of exactly one of w or x.
# This function flips exactly one bit at a position chosen at random:
def flip_random_bit(x):
    return x ^ (1 << randrange(x.bit_length()))

# Multiplicative inverse of a in Z_n* given by Wikipedia article
# def inverse(a, n):
#    (t, new_t, r, new_r) = (0, 1, n, a)
#    while new_r != 0:
#        quotient = r // new_r
#        (t, new_t) = (new_t, t - quotient * new_t)
#        (r, new_r) = (new_r, r - quotient * new_r)
#    if r > 1:
#        return -1 # a is not invertible in Z/nZ
#    else:
#	     return t % n
