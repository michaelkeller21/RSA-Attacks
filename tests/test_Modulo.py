import sys
sys.path.append('..') # puts the python path back a level to parent directory

from Modulo import Modulo

# Defining variables
p = Modulo(7, 3)
q = Modulo(4, 3)

# tests
assert p == q
assert p + q == 1
assert p * q == 1

