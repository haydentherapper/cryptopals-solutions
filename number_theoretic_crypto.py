import random
from Crypto import Random
from Crypto.Hash import SHA256

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

class Client:
    def __init__(self, g, p, k, I, password):
        self.g = g
        self.p = p
        self.k = k
        self.I = I
        self.password = password
        self.secret_a = random.randint(0, p-1)

    def calc_pub_A(self):
        self.A = modexp(base=self.g, exp=self.secret_a, mod=self.p)

    def receive_pub_B_salt(self, B, salt):
        self.B = B
        self.salt = salt

    def calc_hash_A_B(self):
        h = SHA256.new()
        h.update(str(self.A).encode()+str(self.B).encode())
        uH = h.hexdigest()
        self.u = int(uH, 16)

    def calc_shared_key(self):
        h = SHA256.new()
        h.update(self.salt+self.password)
        xH = h.hexdigest()
        x = int(xH, 16)
        v = modexp(self.g, x, self.p)
        S = modexp(self.B - (self.k*v), self.secret_a + (self.u*x), self.p)
        h = SHA256.new()
        h.update(str(S).encode())
        self.K = h.digest()

class Server:
    def __init__(self, g, p, k, I, password):
        self.g = g
        self.p = p
        self.k = k
        self.I = I
        self.password = password
        self.secret_b = random.randint(0, p-1)

    def gen_salt(self):
        self.salt = Random.new().read(16)

    def gen_pass_verifier(self):
        h = SHA256.new()
        h.update(self.salt+self.password)
        xH = h.hexdigest() # Insecure hashed password
        x = int(xH, 16)
        self.v = modexp(self.g, x, self.p) # Password verifier

    def calc_pub_B(self):
        self.B = (self.k * self.v) + modexp(base=self.g, exp=self.secret_b, mod=self.p)

    def receive_pub_A(self, A):
        self.A = A

    def calc_hash_A_B(self):
        h = SHA256.new()
        h.update(str(self.A).encode()+str(self.B).encode())
        uH = h.hexdigest()
        self.u = int(uH, 16)

    def calc_shared_key(self):
        v_u = modexp(self.v, self.u, self.p)
        S = modexp(self.A * v_u, self.secret_b, self.p)
        h = SHA256.new()
        h.update(str(S).encode())
        self.K = h.digest()

class SimplifiedClient:
    def __init__(self, g, p, k, I, password):
        self.g = g
        self.p = p
        self.k = k
        self.I = I
        self.password = password
        self.secret_a = random.randint(0, p-1)

    def calc_pub_A(self):
        self.A = modexp(base=self.g, exp=self.secret_a, mod=self.p)

    def receive_pub_B_salt_u(self, B, salt, u):
        self.B = B
        self.salt = salt
        self.u = u

    def calc_shared_key(self):
        h = SHA256.new()
        h.update(self.salt+self.password)
        xH = h.hexdigest()
        x = int(xH, 16)
        v = modexp(self.g, x, self.p)
        S = modexp(self.B, self.secret_a + (self.u*x), self.p)
        h = SHA256.new()
        h.update(str(S).encode())
        self.K = h.digest()

class SimplifiedServer:
    def __init__(self, g, p, k, I, password):
        self.g = g
        self.p = p
        self.k = k
        self.I = I
        self.password = password
        self.secret_b = random.randint(0, p-1)

    def gen_salt(self):
        self.salt = Random.new().read(16)

    def gen_pass_verifier(self):
        h = SHA256.new()
        h.update(self.salt+self.password)
        xH = h.hexdigest() # Insecure hashed password
        x = int(xH, 16)
        self.v = modexp(self.g, x, self.p) # Password verifier

    def calc_pub_B(self):
        self.B = modexp(base=self.g, exp=self.secret_b, mod=self.p)

    def receive_pub_A(self, A):
        self.A = A

    def calc_hash(self):
        self.u = int.from_bytes(Random.new().read(16), byteorder='big', signed=False)

    def calc_shared_key(self):
        v_u = modexp(self.v, self.u, self.p)
        S = modexp(self.A * v_u, self.secret_b, self.p)
        h = SHA256.new()
        h.update(str(S).encode())
        self.K = h.digest()

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
