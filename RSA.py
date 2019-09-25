# Functions
from Crypto.Util import \
    number  # See https://www.dlitz.net/software/pycrypto/api/current/toc-Crypto.Util.number-module.html
from math import gcd
import sys
from time import time
from powmodn import rec_pow_mod_n, bit_pow_mod_n, mon_pow_mod_n
from util import lcm, Zn_to_ZpxZq, ZpxZq_to_Zn, flip_random_bit
from inverse import inverse, rinv_helper
from random import randint

class RSA:
    def __init__(self, powmodn=bit_pow_mod_n, sign=False):
        print("RSA scheme using {} algorithm".format(powmodn.__name__))
        self.powmodn = powmodn

        if sign:
            self.rsa_verify = self.rsa_encrypt
            self.rsa_sign = self.CRT_rsa_decrypt

    def rsa_encrypt(self, m, public_key):
        n, e = public_key
        return self.powmodn(m, e, n)

    # It's "isomorphic" to the encrypt function! Maybe just reuse the encrypt function.
    def rsa_decrypt(self, c, private_key):
        n, d = private_key
        return self.powmodn(c, d, n)

    def generate_keys(self, bit_length=1024, e=65537):
        p = number.getPrime(bit_length)
        q = number.getPrime(bit_length)
        n = p * q
        # Carmichael's totient function, which is the same as Euler's in this case.
        l = lcm(p - 1, q - 1)
        public_key = (n, e)
        d = inverse(e, l)
        private_key = (n, d)
        return (p, q, n, l, e, d, public_key, private_key)

    def encrypt(self, plaintext_string, public_key):
        return int2string(rsa_encrypt(string2int(plaintext_string), public_key))


    def decrypt(self, ciphertext_string, private_key):
        return int2string(rsa_decrypt(string2int(ciphertext_string), private_key))

    # Square-and-multiply using the CRT. Computes b^m (mod n).
    def CRT_pow_mod_n(self, b, m, n, p, q, faulty=False):
        (u, v) = Zn_to_ZpxZq(b, p, q)

        w = self.powmodn(u, m % (p - 1), p)
        x = self.powmodn(v, m % (q - 1), q)

        if faulty:  # used by the random fault attack
            if randint(0, 1):
                w = flip_random_bit(w)
            else:
                x = flip_random_bit(x)

        return ZpxZq_to_Zn(w, p, x, q, n)

    def CRT_rsa_decrypt(self, c, private_key, p, q, faulty=False):
        n, d = private_key
        return self.CRT_pow_mod_n(c, d, n, p, q, faulty)
