from number_theoretic_crypto import *
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
    assert(server.K == client.K)
    assert(client_h.hexdigest() == server_h.hexdigest())
    print("C36 passed!\n")

if __name__ == '__main__':
    c33()
    c34()
    c35()
    c36()
