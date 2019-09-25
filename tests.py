from RSA import RSA
from util import int2string, string2int
from rt import rt, rt2, rt3, rt4, rt_average
from math import gcd

def test_RSA(message="The quick brown fox jumps over the lazy dog.",
             bit_length=2048, e=65537):
    # Generate a pair of primes
    # Use PyCrypt's library for generating primes for now. If we need to make
    # a home-brew version of these, we will, later...
    print("Generating ", bit_length, "-bit primes...")

    qq = RSA()
    (p, q, n, l, e, d, public_key, private_key) = qq.generate_keys(bit_length, e)

    print("\nOriginal plaintext message: ", message)

    m = string2int(message)
    print("\nEncrypting message...")
    c = qq.rsa_encrypt(m, public_key)
    ciphertext = int2string(c)
    print("  Ciphertext: ", ciphertext)

    print("\nDecrypting message...")
    [m2, running_time] = rt2(qq.rsa_decrypt, c, private_key)
    message2 = int2string(m2)
    print("  Message decrypted by rsa_decrypt: ", message2)
    print("  Running time for rsa_decrypt: ", running_time)

    print("\nDecrypting message using Chinese Remainder Theorem...")
    [m3, running_time] = rt4(qq.CRT_rsa_decrypt, c, private_key, p, q)
    message3 = int2string(m3)
    print("  Message decrypted by CRT_rsa_decrypt: ", message3)
    print("  Running time for CRT_rsa_decrypt: ", running_time)

    return (p, q, n, l, e, d, public_key, private_key, m, c, message, ciphertext)

def test_RSA_sign(bit_length=1024, e=65537):
    # -------------------------------------------------------------------------
    # Mount the random fault attack decribed in section 5.2
    #
    # # Signing and verifying are just the same functions as decrypting and encrypting:
    # CRT_rsa_sign = CRT_rsa_decrypt
    # rsa_verify = rsa_encrypt

    qq = RSA(sign=True)

    print("\n\n-------------------------------------------------------------")
    print("\nThe random fault attack:")
    print("Generating", bit_length, "-bit keys...")
    (p, q, n, l, e, d, public_key, private_key) = qq.generate_keys(bit_length, e)

    message = "Please attach your signature."
    print("\nAlice asks Bob to sign this message:\n\n\t", message)
    m = string2int(message)
    print("\nIn numeric form, this message is m =", m)

    print("\nNormally, Bob signs the message with his private key. The signature is ")
    s = qq.rsa_sign(m, private_key, p, q)
    print("\ns =", s)

    print("\nAlice can verify this signature using the public key:")
    print("\nrsa_verify(s, public_key) = ", qq.rsa_verify(s, public_key))

    print("\nIt is the same as the original message m.")

    print("\nThe random fault attack works on the CRT implementation of rsa_sign")
    print("(same as rsa_decrypt) function.")
    print("With CRT, RSA signing/decrypting first sends the message m in Z_n*")
    print("to the corresponding element (u, v) in Z_p* x Z_q*.")
    print("Exponentiation is done in Z_p* x Z_q* where it is less computationally expensive:")
    print("\n\t x = u ^ (d mod (p - 1))")
    print("\n\t w = v ^ (d mod (q - 1))")
    print("\nAfterwards, send (x, w) in Z_p* x Z_q* to the corresponding element in Z_n*.")
    print("This can be done using the extended euclidean algorithm, where we find r and t,")
    print("the inverses of p in Z_q*, and q in Z_p*, respectively, so that")
    print("\n\trpx + tqw = w (mod p) = x (mod q)")
    print("\nis the corresponding element in Z_n*. This is the signature s = m ^ d (mod n).")
    print("Note that spx = 0 (mod p) and tqw = 0 (mod q). The random fault attack")
    print("can be mounted if exactly one of w or x can be corrupted.")

    print("\nSuppose exactly one of x or w has bit errors, say x becomes x'.")
    print("Then Alice doesn't get the original message m when she verifies the signature.")
    print("Instead of s^e (mod n) = m, Alice gets ")
    print("\n\tm' = (rpx' + tqw)^e (mod n).")
    print("\t   = (rpx')^e + (tpq)^e (mod n) # All cross products are 0 mod n = pq.")
    print("\nThe difference between this and m = s^d = (rpx) ^ e + (tpq) ^ e (mod n)")
    print("is (rpx') ^ e - (rpx)^e (mod n). This difference is equivalent to 0 (mod p),")
    print("and just as important, this difference is nonzero. That is,")
    print("\n\tm - verify(s', public_key) = 0 (mod p) and is nonzero.")
    print("\nThus, computing gcd(n, m - verify(s' public_key)) reveals one of the")
    print("factors of n.")
    print("\nWhen we introduce even a single bit error in x or w, we don't get the")
    print("original message m when we verify the corrupted signature.")

    print("\nThe CRT_rsa_sign function has a 'feature' that lets us introduce a")
    print("bit error at a random position in either x or w:")
    print("\n\ts1 = CRT_rsa_sign(m, private_key, p, q, faulty = True)")

    s1 = qq.rsa_sign(m, private_key, p, q, faulty=True)  # random bit flip

    print("\nThe corrupted signature: s' =", s1)

    m1 = qq.rsa_verify(s1, public_key)

    print("\nAlice doesn't get the original message back when she verifies s':")
    print("\nm' = verify(s', public_key) =", m1)

    print("\nThe difference between this and the original message is equivalent to 0")
    print("modulo one of the prime factors of n. Alice can recover the factorization by computing the gcd.")

    recovered_factor = gcd(n, m - m1)

    print("\ngcd(n, m - m') =", recovered_factor)
    print("\nIt should be equal to one of the prime factors of n:")
    print("\np =", p)
    print("\nq =", q)

def create_decrypt_running_time_table(message, e, start, stop, step, trials):

    qq = RSA()

    m = string2int(message)

    print("bit_length,Naïve_fast_exponentiation,CRT_fast_exponentiation")

    for bit_length in range(start, stop + 1, step):
        sum_rt = sum_rt_crt = 0

        for i in range(trials):
            (p, q, n, l, e, d, public_key, private_key) = qq.generate_keys(bit_length, e)
            c = qq.rsa_encrypt(m, public_key)

            # Accumulate naïve recursive running times across trials
            sum_rt += rt2(qq.rsa_decrypt, m, private_key)[1]

            # ditto for CRT
            sum_rt_crt += rt4(qq.CRT_rsa_decrypt, c, private_key, p, q)[1]

        print(bit_length, sum_rt / trials, sum_rt_crt / trials, sep=',')
