# Functions
import sys
from RSA import RSA
from tests import test_RSA, test_RSA_sign, create_decrypt_running_time_table, prompt_for_powmodn
from util import string2int, int2string
from powmodn import rec_pow_mod_n, bit_pow_mod_n, mon_pow_mod_n

sys.setrecursionlimit(16384)

val = int(input("\n1 Test RSA Encryption\
           \n2 Test RSA Signature\
           \n3 Generate RSA Decryption CSV\n\ninput: "))

if val:
    if val == 1:
        print("\n\n-------------------------------------------------------------")
        print("RSA decryption using the Chinese Remainder Theorem (CRT)")

        # prompt user input for powmodn algorithm type and assign to alg obj
        alg = prompt_for_powmodn()

        # Run the test with default parameters and save the results:
        (p, q, n, l, e, d, public_key, private_key, m, c, message, ciphertext) = test_RSA(powmodn=alg)

    if val == 2:
        print("\n\n-------------------------------------------------------------")
        print("Creating csv table of running times for rsa_decrypt and CRT_rsa_decrypt...\n")

        # prompt user input for powmodn algorithm type and assign to alg obj
        alg = prompt_for_powmodn()

        create_decrypt_running_time_table("Testing 123", 65537, 128, 1280, 128, 5, powmodn=alg)
    if val == 3:
        # Test fault attack
        test_RSA_sign()
