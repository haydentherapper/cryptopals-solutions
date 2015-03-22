from crypto import *
from sha1py import *
from md4py import *
import random, requests

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
    print("MAC (SHA1) of message:", mac)
    # Assuming key length of 16...
    pad = create_MD_padding(b'A' * 16 + message, length_endian='big')
    addition = b';admin=true'
    new_message = message + pad + addition # What we send to the server
    server_side_mac = sha1_mac(key, new_message).hexdigest()
    print("MAC of server-side auth:", server_side_mac)
    # Fix registers based on previous hash, then continue to hash with new block
    our_mac = sha1(addition, state=(mac, len(b'A'*16+message+pad))).hexdigest()
    print("Spoofed MAC without access to key:", our_mac)
    assert(our_mac == server_side_mac)
    print("C29 passed!\n")

def c30():
    # Assume we know the key size, it would be easy to bruteforce anyways
    key = gen_AES_key() # Hidden
    message = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    byte_mac = md4_mac(key, message)
    mac = hexdigest(byte_mac)
    print("MAC (MD4) of message:", mac)
    # Assuming key length of 16...
    pad = create_MD_padding(b'A' * 16 + message, length_endian='little')
    addition = b';admin=true'
    new_message = message + pad + addition # What we send to the server
    server_side_mac = hexdigest(md4_mac(key, new_message))
    print("MAC of server-side auth:", server_side_mac)
    # Switching between endians is miserable...since we are given big-endian
    # registers, we must unwrap the hash as little-endian registers since
    # each register, as big-endian, will later be outputed to little-endian
    state = list(map(lambda x: struct.unpack('<I', x)[0], \
        [byte_mac[i:i+4] for i in range(0, len(byte_mac), 4)]))
    # Fix registers based on previous hash, then continue to hash with new block
    our_mac = hexdigest(MD4(addition, fake_byte_len=len(b'A'*16+new_message), state=state))
    print("Spoofed MAC without access to key:", our_mac)
    assert(our_mac == server_side_mac)
    print("C30 passed!\n")

def c31():
    fileName = b'foobar'
    print("Bruteforcing HMAC through timing attack...")
    mac = b''
    found_mac = False
    url = 'http://localhost:5000/test'
    while not found_mac:
        best_time = 0
        best_char = None
        for i in range(256):
            payload = {'file': fileName.decode(), 'signature': hexdigest(mac + bytes([i]))}
            start = time.time()
            r = requests.get(url, params=payload)
            end = time.time()
            if r.status_code == 200:
                best_char = i
                found_mac = True
                break
            elif end - start > best_time:
                best_time = end - start
                best_char = i
        mac += bytes([best_char])
        print("HMAC so far:", hexdigest(mac))
    print("Bruteforced HMAC:", hexdigest(mac))
    print("C31 passed!\n")

def c32():
    print("Bruteforcing HMAC through harder timing attack...")
    print("This will take a VERY long time!")
    fileName = b'foobar'
    mac = b''
    found_mac = False
    url = 'http://localhost:5000/test'
    while not found_mac:
        best = {} # Maps char to time
        for i in range(256):
            total_time = 0 # Try for some number of times
            payload = {'file': fileName.decode(), 'signature': hexdigest(mac + bytes([i]))}
            for _ in range(10):
                start = time.time()
                r = requests.get(url, params=payload)
                end = time.time()
                if r.status_code == 200:
                    best[i] = 10000 # Large value = max time
                    found_mac = True
                    break
                else:
                    if i in best:
                        best[i] += (end - start) / 10
                    else:
                        best[i] = (end - start) / 10
        mac += bytes([max(best, key=best.get)])
        print("HMAC so far:", hexdigest(mac))
    print("Bruteforced HMAC:", hexdigest(mac))
    print("C32 passed!\n")

if __name__ == '__main__':
    c25()
    c26()
    c27()
    c28()
    c29()
    c30()
    c31()
    c32()
