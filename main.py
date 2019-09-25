# Functions
import sys
from powmodn import rec_pow_mod_n, mon_pow_mod_n, bit_pow_mod_n
from RSA import RSA
from tests import test_RSA, test_RSA_sign, create_decrypt_running_time_table
from util import string2int, int2string

sys.setrecursionlimit(16384)

print("\n\n-------------------------------------------------------------")
print("RSA decryption or signing using the Chinese Remainder Theorem (CRT)")

# Run the test with default parameters and save the results:
(p, q, n, l, e, d, public_key, private_key, m, c, message, ciphertext) = test_RSA()

print("\n\n-------------------------------------------------------------")
print("Creating csv table of running times for rsa_decrypt and CRT_rsa_decrypt...\n")

# Run it
create_decrypt_running_time_table("Testing 123", 65537, 128, 1280, 128, 5)

# Test fault attack
test_RSA_sign()
