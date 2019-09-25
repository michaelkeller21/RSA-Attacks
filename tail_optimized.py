from tailcaller import TailCall, TailCaller

@TailCaller
# Currently failing implementation of tail recursion optimized rec_pow_mod_n
def rec_pow_mod_n1(b, m):
    if not m:
        return 1

    if m == 1:
        return m

    elif not (m % 2):
        return rec_pow_mod_n(b*b % n, m // 2, n)

    else:
        return rec_pow_mod_n(b*b % n, (m - 1) // 2, n)
