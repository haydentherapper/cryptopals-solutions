from crypto import *
from sha1py import *
import random

def c25():
    with open('texts/c25text.txt', 'r') as file:
        data = file.read()
    input = hex2b(b642hex(data))
    ecb_key = "YELLOW SUBMARINE"
    pt = pkcs7_rm_padding(dec_AES_ECB(input, ecb_key))

    key = gen_AES_key()
    ciphertext = enc_AES_CTR(pt, key)
    # 'edit' the ciphertext by overwriting with plaintext \x00
    # 'edit' hides the key, but we can use a zero offset and overwrite the whole pt
    new_pt = b'\x00' * len(ciphertext)
    new_ciphertext = edit(ciphertext, key, 0, new_pt)
    # Since c1 = pt1 ^ CTR(key, IV) and c2 = pt2 ^ CTR(key, IV), c1 ^ c2 = pt1 ^ pt2
    extracted_pt = fixed_xor(ciphertext, new_ciphertext)
    assert(pt == extracted_pt)
    print("C25 passed!\n")

def c26():
    injection_string = "admin=true;".encode()
    ciphertext, key = ctr_bitflip(injection_string)
    result = dec_userdata_ctr(ciphertext, key)
    print("Confirming \"admin=true\" is in the plaintext")
    assert(result)
    print("C26 passed!\n")

def c27():
    plaintext = (b'A' * 16) + (b'\xff' * 16) + (b'A' * 16)
    key = gen_AES_key()
    recovered_key = recover_iv_key_cbc(plaintext, key)
    assert(key == recovered_key)
    print("C27 passed!\n")

def c28():
    message = b'I love cryptography'
    key = gen_AES_key()
    mac = sha1_mac(key, message)
    assert(mac.digest() == sha1_mac(key, message).digest())
    assert(mac.hexdigest() == sha1_mac(key, message).hexdigest())
    other_message = b'I don"t love cryptography which is a lie'
    assert(mac.digest() != sha1_mac(key, other_message).digest())
    assert(mac.hexdigest() != sha1_mac(key, other_message).hexdigest())
    other_key = gen_AES_key()
    assert(mac.digest() != sha1_mac(other_key, message).digest())
    assert(mac.hexdigest() != sha1_mac(other_key, message).hexdigest())
    print("C28 passed!\n")

def c29():
    # Assume we know the key size, it would be easy to bruteforce anyways
    key = gen_AES_key() # Hidden
    message = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    mac = sha1_mac(key, message).hexdigest()
    print("MAC of message:", mac)
    # Assuming key length of 16...
    pad = bin_to_hex(create_MD_padding(b'A' * 16 + message))
    addition = b';admin=true'
    new_message = message + pad + addition # What we send to the server
    server_side_mac = sha1_mac(key, new_message).hexdigest()
    print("MAC of server-side auth:", server_side_mac)
    # Fix registers based on previous hash, then continue to hash with new block
    our_mac = sha1(addition, state=(mac, len(b'A'*16+message+pad))).hexdigest()
    print("Spoofed MAC without access to key:", our_mac)
    assert(our_mac == server_side_mac)
    print("C29 passed!\n")

if __name__ == '__main__':
    c25()
    c26()
    c27()
    c28()
    c29()
