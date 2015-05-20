from number_theoretic_crypto import *
import binascii
import math
from Crypto.Cipher import AES
from Crypto.Hash import SHA, SHA256, HMAC
from Crypto import Random

def c33():
    g = 2
    p = int(''.join(
        """ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
        e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
        3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
        6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
        24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
        c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
        bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
        fffffffffffff"""
        .split()), 16)
    alice = Alice(g, p)
    alice.calc_pub_A()
    bob = Bob(g, p)
    bob.calc_pub_B()
    alice.calc_key(bob.B)
    bob.calc_key(alice.A)
    assert(alice.s == bob.s)
    print("C33 passed!\n")

def c34():
    g = 2
    p = int(''.join(
        """ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
        e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
        3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
        6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
        24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
        c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
        bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
        fffffffffffff"""
        .split()), 16)
    alice = Alice(g, p)
    alice.calc_pub_A()
    bob = Bob(g, p)
    bob.calc_pub_B()
    alice.calc_key(bob.B)
    bob.calc_key(alice.A)

    # Encrypt a message for Alice under Bob's private key
    h = SHA.new()
    h.update(str(bob.s).encode())
    key = bytes(bytearray(h.digest())[:16])
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    msg = b'yellow submarine'
    enc_msg = cipher.encrypt(msg) + iv

    # Alice can now decrypt the message with the shared key
    h = SHA.new()
    h.update(str(alice.s).encode())
    key = bytes(bytearray(h.digest())[:16])
    iv = enc_msg[-16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)

    msg_bob = cipher.decrypt(enc_msg[:-16])
    assert(msg_bob == b'yellow submarine')

    # Encrypt a message for Bob under Alice's private key
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    msg = b'purple submarine'
    enc_msg = cipher.encrypt(msg) + iv

    # Bob can now decrypt
    h = SHA.new()
    h.update(str(bob.s).encode())
    key = bytes(bytearray(h.digest())[:16])
    iv = enc_msg[-16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)

    msg_bob = cipher.decrypt(enc_msg[:-16])
    assert(msg_bob == b'purple submarine')

    # Now we add a middleman that can decrypt messages
    alice = Alice(g, p)
    alice.calc_pub_A()
    bob = Bob(g, p)
    bob.calc_pub_B()
    bob.calc_key(p) # Middleman exchanges Alice's 'A' for 'p'
    alice.calc_key(p) # Exchange of Bob's 'B' for 'p'
    # The key 's' is now 0: s = b^e % m = p^x % p = 0

    # Encrypt a message for Alice under Bob's private key
    h = SHA.new()
    h.update(str(bob.s).encode())
    key = bytes(bytearray(h.digest())[:16])
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    msg = b'yellow submarine'
    enc_msg_bob = cipher.encrypt(msg) + iv

    # Encrypt a message for Bob under Alice's private key
    h = SHA.new()
    h.update(str(alice.s).encode())
    key = bytes(bytearray(h.digest())[:16])
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    msg = b'purple submarine'
    enc_msg_alice = cipher.encrypt(msg) + iv

    # Now, MIDDLEMAN can decrypt
    h = SHA.new()
    h.update(str(0).encode())
    key = bytes(bytearray(h.digest())[:16])
    iv = enc_msg_bob[-16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)

    msg_bob = cipher.decrypt(enc_msg_bob[:-16])
    assert(msg_bob == b'yellow submarine')

    iv = enc_msg_alice[-16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)

    msg_bob = cipher.decrypt(enc_msg_alice[:-16])
    assert(msg_bob == b'purple submarine')

    print("Middleman was successful in decrypting messages!")
    print("C34 passed!\n")

def c35():
    g = 2
    p = int(''.join(
        """ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
        e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
        3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
        6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
        24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
        c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
        bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
        fffffffffffff"""
        .split()), 16)
    # As a man in the middle, let g = 1
    # Therefore, g^a % p, g^b % p = 1, which makes s = 1
    alice = Alice(1, p)
    alice.calc_pub_A()
    bob = Bob(1, p)
    bob.calc_pub_B()
    alice.calc_key(bob.B)
    bob.calc_key(alice.A)

    assert(bob.s == 1 and alice.s == 1)

    # As a man in the middle, let g = p
    # Therefore, g^a % p, g^b % p = 0, which makes s = 0
    alice = Alice(p, p)
    alice.calc_pub_A()
    bob = Bob(p, p)
    bob.calc_pub_B()
    alice.calc_key(bob.B)
    bob.calc_key(alice.A)

    assert(bob.s == 0 and alice.s == 0)

    # As a man in the middle, let g = p - 1
    # Therefore:
    #   a % 2 == 0: g^a % p = 1 | 6^2 % 7 = 1
    #   a % 2 == 1: g^a % p = p - 1 | 6^3 % 7 = 6
    #   When either A or B = 1, then s = 1
    #   Otherwise, s = p - 1
    alice = Alice(p - 1, p)
    alice.calc_pub_A()
    bob = Bob(p - 1, p)
    bob.calc_pub_B()
    alice.calc_key(bob.B)
    bob.calc_key(alice.A)

    assert((alice.s == 1 or alice.s == p - 1) and alice.s == bob.s)

    print("C35 passed!\n")

def c36():
    print("1. Agree on shared values N, g, k, I (email) and P (password)")
    g = 2
    p = int(''.join(
        """ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
        e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
        3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
        6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
        24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
        c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
        bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
        fffffffffffff"""
        .split()), 16)
    k = 3
    I = b'me'
    password = b'yellow submarine'
    client = Client(g, p, k, I, password)
    server = Server(g, p, k, I, password)
    print("2. Server generates salt, hashes salt|password, and creates password verifier")
    server.gen_salt()
    server.gen_pass_verifier()
    print("3. Client sends username and public A")
    client.calc_pub_A()
    server.receive_pub_A(client.A)
    print("4. Server sends salt and public B")
    server.calc_pub_B()
    client.receive_pub_B_salt(server.B, server.salt)
    print("5. Both compute hash of A|B")
    client.calc_hash_A_B()
    server.calc_hash_A_B()
    print("6. Client generates shared key")
    client.calc_shared_key()
    print("7. Server generates shared key")
    server.calc_shared_key()

    print("8. Authenticate by checking that both keys match")
    client_h = HMAC.new(client.K, msg=client.salt, digestmod=SHA256)
    server_h = HMAC.new(server.K, msg=server.salt, digestmod=SHA256)
    assert(client_h.hexdigest() == server_h.hexdigest())
    print("C36 passed!\n")

def c37():
    print("No need for a password with 'A = 0'")
    g = 2
    p = int(''.join(
        """ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
        e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
        3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
        6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
        24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
        c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
        bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
        fffffffffffff"""
        .split()), 16)
    k = 3
    I = b'me'
    password = b'who knows'
    client = Client(g, p, k, I, password)
    server = Server(g, p, k, I, password)

    server.gen_salt()
    server.gen_pass_verifier()

    client.calc_pub_A()
    # Send fake value for A
    server.receive_pub_A(0) # client.A = 0

    server.calc_pub_B()
    client.receive_pub_B_salt(server.B, server.salt)

    client.calc_hash_A_B()
    server.calc_hash_A_B()

    client.calc_shared_key()

    # We know that A = 0, so S = ((A * k^u) ^ b) % p = 0
    # Therefore, K = SHA256(S) = SHA256(0)
    server.calc_shared_key()

    fake_client_h = HMAC.new(SHA256.new(str(0).encode()).digest(), 
                                msg=client.salt, digestmod=SHA256)
    server_h = HMAC.new(server.K, msg=server.salt, digestmod=SHA256)
    assert(fake_client_h.hexdigest() == server_h.hexdigest())

    print("No need for a password with 'A = p' either")
    client = Client(g, p, k, I, password)
    server = Server(g, p, k, I, password)

    server.gen_salt()
    server.gen_pass_verifier()

    client.calc_pub_A()
    # Send fake value for A
    server.receive_pub_A(p) # client.A = p

    server.calc_pub_B()
    client.receive_pub_B_salt(server.B, server.salt)

    client.calc_hash_A_B()
    server.calc_hash_A_B()

    client.calc_shared_key()

    # We know that A = p, so S = ((p * k^u) ^ b) % p = 0
    # Therefore, K = SHA256(S) = SHA256(0)
    server.calc_shared_key()

    fake_client_h = HMAC.new(SHA256.new(str(0).encode()).digest(), 
                                msg=client.salt, digestmod=SHA256)
    server_h = HMAC.new(server.K, msg=server.salt, digestmod=SHA256)
    assert(fake_client_h.hexdigest() == server_h.hexdigest())
    print("C37 passed!\n")

def c38():
    print("Run with a simplified client and server first")
    g = 2
    p = int(''.join(
        """ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
        e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
        3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
        6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
        24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
        c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
        bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
        fffffffffffff"""
        .split()), 16)
    k = 3
    I = b'me'
    password = b'letmein'
    client = SimplifiedClient(g, p, k, I, password)
    server = SimplifiedServer(g, p, k, I, password)

    server.gen_salt()
    server.gen_pass_verifier()

    client.calc_pub_A()
    server.receive_pub_A(client.A) 

    server.calc_pub_B()
    server.calc_hash()
    client.receive_pub_B_salt_u(server.B, server.salt, server.u)

    client.calc_shared_key()

    # We know that A = 0, so S = ((A * k^u) ^ b) % p = 0
    # Therefore, K = SHA256(S) = SHA256(0)
    server.calc_shared_key()

    client_h = HMAC.new(client.K, msg=client.salt, digestmod=SHA256)
    server_h = HMAC.new(server.K, msg=server.salt, digestmod=SHA256)
    assert(client_h.hexdigest() == server_h.hexdigest())

    print("Now, as a middleman, fake server responses to get client's HMAC")
    client = SimplifiedClient(g, p, k, I, password)
    fake_server = SimplifiedServer(g, p, k, I, password) # Technically doesn't know password

    fake_server.gen_salt()
    fake_server.gen_pass_verifier()

    client.calc_pub_A()
    fake_server.receive_pub_A(client.A)

    fake_server.calc_pub_B()
    fake_server.calc_hash()
    client.receive_pub_B_salt_u(fake_server.B, fake_server.salt, fake_server.u)

    client.calc_shared_key()
    fake_server.calc_shared_key()

    client_h = HMAC.new(client.K, msg=client.salt, digestmod=SHA256)
    print("Without password verifier, run dictionary attack")
    # HMAC(K, salt) = HMAC(SHA256(S), salt) = HMAC(SHA256((A * v^u)^b % p), salt)
    # v = g^x % p = g^(SHA256(salt|password)) % p
    PASSWORD_LIST = ['123456', 'password', '12345', '12345678', 'qwerty', 
                        '123456789', '1234', 'baseball', 'dragon', 'football', 
                        '1234567', 'monkey', 'letmein', 'abc123', '111111', 
                        'mustang', 'access', 'shadow', 'master', 'michael', 
                        'superman', '696969', '123123', 'batman', 'trustno1']
    for password in PASSWORD_LIST:
        xH = SHA256.new(fake_server.salt + password.encode()).hexdigest()
        x = int(xH, 16)
        v = modexp(fake_server.g, x, fake_server.p)
        v_u = modexp(v, fake_server.u, fake_server.p)
        S = modexp(fake_server.A * v_u, fake_server.secret_b, fake_server.p)
        K = SHA256.new(str(S).encode()).digest()
        server_guess = HMAC.new(K, msg=fake_server.salt, digestmod=SHA256)
        if server_guess.hexdigest() == client_h.hexdigest():
            print('Bruteforced password: ' + password)
            break

    print("C38 passed!\n")

def c39():
    print("Testing RSA...")
    e, d, n = rsa_setup()
    message = 42
    c = rsa_encrypt(message, e, n)
    dec_message = rsa_decrypt(c, d, n)
    assert(dec_message == message)

    message = int(binascii.hexlify(b"I love RSA"), 16)
    c = rsa_encrypt(message, e, n)
    dec_message = rsa_decrypt(c, d, n)
    assert(dec_message == message)
    print("C39 passed!\n")

def c40():
    print("Implementation of E=3 RSA Broadcast attack")
    message = 42 # Assume message < N_i
    e1, d1, n1 = rsa_setup()
    c1 = rsa_encrypt(message, e1, n1)
    e2, d2, n2 = rsa_setup()
    c2 = rsa_encrypt(message, e2, n2)
    e3, d3, n3 = rsa_setup()
    c3 = rsa_encrypt(message, e3, n3)
    print("Using Chinese Remainder Theorem, we solve for a common ciphertext C")
    print("C is congruent to M^e = M^3 mod n1*n2*n3")
    result = (c1 * (n2*n3) * invmod(n2*n3, n1)) + \
             (c2 * (n1*n3) * invmod(n1*n3, n2)) + \
             (c3 * (n1*n2) * invmod(n1*n2, n3)) # Don't take modulu, since M^3 < n1*n2*n3
    result = result % (n1*n2*n3)
    # All solutions are congruent to result mod N, so M^3 is congruent to this
    dec_message = math.ceil(math.pow(result, 1/3))
    assert(message == dec_message)
    print("C40 passed!\n")

if __name__ == '__main__':
    c33()
    c34()
    c35()
    c36()
    c37()
    c38()
    c39()
    c40()
