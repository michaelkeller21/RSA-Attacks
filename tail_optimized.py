from tailcaller import TailCall, TailCaller

# Currently failing implementation of tail recursion optimized rec_pow_mod_n
@TailCaller
def rec_pow_mod_n1(b, m):
    if not m:
        return 1

    if m == 1:
        return m

    elif not (m % 2):
        return rec_pow_mod_n(b*b % n, m // 2, n)

    else:
        return rec_pow_mod_n(b*b % n, (m - 1) // 2, n)

@TailCaller
def rec_pow_mod_n2_helper(b, m, n, acc):
    if not m:
        return acc

    if not (m % 2):
        m = m // 2
        acc = acc**2
    else:
        m = m - 1
        acc = b*acc
    return TailCall(rec_pow_mod_n_helper, b, m, n, acc % n)

def rec_pow_mod_n2(b, m, n):
  acc = b
  return rec_pow_mod_n_helper(b, m, n, acc)
