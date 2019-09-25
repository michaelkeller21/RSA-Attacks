from tailcaller import TailCall, TailCaller

# uses tailcaller class and function to perform tail-recursion
@TailCaller # tailcaller class decorator
def tail_rec_pow_mod_n_helper(b, m, n, acc):
    if not m:
        return acc

    if not (m % 2):
        m = m // 2
        acc = acc**2
    else:
        m = m - 1
        acc = b*acc
    return TailCall(tail_rec_pow_mod_n_helper, b, m, n, acc % n)

def tail_rec_pow_mod_n(b, m, n):
  acc = b
  return tail_rec_pow_mod_n_helper(b, m, n, acc)
