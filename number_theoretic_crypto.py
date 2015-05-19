import random

class Alice:
    def __init__(self, g, p):
        self.g = g
        self.p = p
        self.secret_a = random.randint(0, p-1)

    def calc_pub_A(self):
        self.A = modexp(base=self.g, exp=self.secret_a, mod=self.p)

    def calc_key(self, B):
        self.s = modexp(base=B, exp=self.secret_a, mod=self.p)

class Bob:
    def __init__(self, g, p):
        self.g = g
        self.p = p
        self.secret_b = random.randint(0, p-1)

    def calc_pub_B(self):
        self.B = modexp(base=self.g, exp=self.secret_b, mod=self.p)

    def calc_key(self, A):
        self.s = modexp(base=A, exp=self.secret_b, mod=self.p)

# Fast Right-to-Left modular exponentiation
# Runs in O(log(exp))
def modexp(base,exp,mod):
    c = 1
    base = base % mod
    while exp > 0:
        if exp % 2 == 1:
            c = (c * base) % mod
        exp = exp >> 1
        base = (base * base) % mod
    return c
