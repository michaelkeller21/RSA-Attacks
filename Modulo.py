class Modulo:
    def __init__(self, val, n):
        self.N = n
        self.val = val

    def __mul__(self, other):
        return (self.val * other.val) % self.N

    def __add__(self, other):
        return (self.val + other.val) % self.N

    def __eq__(self, other):
        if self.val % self.N == other.get_val() % other.get_mod():
            return True
        return False

    def set_mod(self, n):
        self.N = n

    def get_mod(self):
        return self.N

    def get_val(self):
        return self.val
