from number_theoretic_crypto import *
import random

def c41():
    # C' = ((S**E % N) * C) % N
    # Decoding C', we get P'
    # P = P'/S % N, since P' = (P*S) % N
    print("Unpadded message attack")
    message = 123456789
    e, d, n = rsa_setup()
    c = rsa_encrypt(message, e, n)
    S = random.randint(1,12345678) % n
    c_prime = (modexp(S, e, n) * c) % n
    p_prime = rsa_decrypt(c_prime, d, n)
    p = (p_prime * invmod(S, n)) % n
    assert(p == message)
    print("C41 passed!\n")

def c42():
    print("Implementation of Bleichenbacher's e=3 RSA Attack")
    

if __name__ == '__main__':
    c41()
