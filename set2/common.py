import binascii
import base64
import string, sys, math, itertools
from Crypto.Cipher import AES
from Crypto import Random
from random import randint

def hex2b(hex):
    return binascii.unhexlify(hex)
    
def b2hex(b):
    return binascii.hexlify(b)

def hex2b64(hex):
    bin_str = binascii.unhexlify(hex.encode('utf8'))
    return base64.b64encode(bin_str).decode('utf8')

def b642hex(b64):
    bin_str = base64.b64decode(b64.encode('utf8'))
    return binascii.hexlify(bin_str).decode('utf8')    

def fixed_xor(b_str1, b_str2):
    return bytes([x ^ y for x,y in zip(b_str1, b_str2)])

def get_freq(letter):
    letter_freqs = {
        'E': .1202,
        'T': .0910,
        'A': .0812,
        'O': .0768,
        'I': .0731,
        'N': .0695,
        'S': .0628,
        'R': .0602,
        'H': .0592,
        'D': .0432,
        'L': .0398,
        'U': .0288,
        'C': .0271,
        'M': .0261,
        'F': .0230,
        'Y': .0211,
        'W': .0209,
        'G': .0203,
        'P': .0182,
        'B': .0149,
        'V': .0111,
        'K': .0069,
        'X': .0017,
        'Q': .0011,
        'J': .0010,
        'Z': .0007
    }
    return letter_freqs[letter]

def score(i):
    tot_score = 0
    input = i.upper()
    tot_score = sum(
        abs((float(input.count(c.encode()) / len(input))) - get_freq(c)) 
        for c in string.ascii_uppercase)
    
    percent_letters = \
        len([x for x in input if 
            ord('A') <= x <= ord('Z') or x == ord(' ')])
    
    return (1 - tot_score) + float(percent_letters / len(input))

def byte_xor_cipher_with_key(b_str):
    max_score = 0
    message = ''
    key = ''
    for c in range(256):
        xor_str = chr(c).encode('utf8') * len(b_str)
        dec = fixed_xor(b_str, xor_str)
        if score(dec) > max_score:
            max_score = score(dec)
            message = dec
            key = chr(c)
    return (message, key)

def byte_xor_cipher(b_str):
    return byte_xor_cipher_with_key(b_str)[0]
    
def detect_xor(lines):
    result = max([(score(byte_xor_cipher(hex2b(line))), line) 
                    for line in lines], key = lambda x: x[0])
    return result[1]

def repeating_key_xor(pt, key):
    chunks = [pt[i:i+len(key)] for i in range(0, len(pt), len(key))]
    return b''.join([fixed_xor(chunk, key) for chunk in chunks])

def hamming_distance(b_str1, b_str2):
    return sum([bin(x).count("1") 
        for x in [b1 ^ b2 for b1,b2 in zip(b_str1, b_str2)]])
    
def find_repeating_xor_key(b_str):
    mapping = {}
    for keysize in range(2,41):
        chunks = [b_str[i*keysize:(i+1)*keysize] for i in range(4)]
        h_dst = 0
        chunks_perm = list(itertools.permutations(chunks, 2))
        h_dst += sum(float(hamming_distance(chunk[0], chunk[1]) / keysize) 
            for chunk in chunks_perm)
        h_dst /= len(chunks_perm)
        mapping[keysize] = h_dst
    
    keysize = ([w for w in sorted(mapping, key = mapping.get)][0])
    chunks = [b_str[i:i+keysize] for i in range(0, len(b_str), keysize)]

    final_key = ''
    for i in range(len(max(chunks, key=len))):
        block = bytes([ch[i] for ch in chunks if i < len(ch)])
        final_key += byte_xor_cipher_with_key(block)[1]
    return final_key

def dec_AES_ECB(b_str, key):
    aes = AES.new(key, AES.MODE_ECB)
    return aes.decrypt(b_str)

def enc_AES_ECB(b_str, key):
    aes = AES.new(key, AES.MODE_ECB)
    return aes.encrypt(b_str)

def find_repeated_ECB(b_str_list):
    for data in b_str_list:
        blocks = [data[i:i+16] for i in range(0, len(data), 16)]
        if len(blocks) != len(set(blocks)):
            return data    

# SET 2

def pkcs7_padding(b_str, pad_len):
    return b_str + \
        (chr(pad_len - len(b_str)) * (pad_len - len(b_str))).encode()

def rm_pad(b_str):
    last_byte = b_str[-1]
    if (last_byte <= len(b_str)):
        padding = b_str[-last_byte:]
        if (len(set(padding)) == 1):
            return b_str[:-last_byte]
        else:
            return b_str
    else:
        return b_str

def enc_AES_CBC(plaintext, key, iv=bytes(16)):
    blocks = [plaintext[i:i+16] for i in range(0, len(plaintext), 16)]
    ciphertext = b''
    for i in range(len(blocks)):
        block = blocks[i]
        if len(block) < 16:
            block = pkcs7_padding(block, 16)
        if i == 0:
            ciphertext += enc_AES_ECB(fixed_xor(block, iv), key) 
        else:
            ciphertext += enc_AES_ECB(fixed_xor(block, 
                                    ciphertext[(i-1)*16:i*16]), key)
    return ciphertext

def dec_AES_CBC(ciphertext, key, iv=bytes(16)):
    blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
    plaintext = b''
    for i in range(len(blocks)):
        block = blocks[i]
        if i == 0:
            plaintext += fixed_xor(dec_AES_ECB(block, key), iv)
        elif i == (len(blocks) - 1):
            pt = rm_pad(fixed_xor(dec_AES_ECB(block, key), blocks[i-1]))
            plaintext += pt
        else:
            plaintext += fixed_xor(dec_AES_ECB(block, key), blocks[i-1])
    return plaintext

def gen_AES_key(keysize = 16):
    return Random.new().read(keysize)

def enc_ECB_or_CBC(plaintext):
    key = gen_AES_key()
    prefix = bytes([randint(0, 255) for i in range(randint(5,10))])
    suffix = bytes([randint(0, 255) for i in range(randint(5,10))])
    plaintext = prefix + plaintext + suffix

    # Pad for ECB
    blocks = [plaintext[i:i+16] for i in range(0, len(plaintext), 16)]
    blocks[-1] = pkcs7_padding(blocks[-1], 16)
    plaintext = b''.join(blocks)

    if randint(0,1) == 0:
        print("ECB mode")
        return enc_AES_ECB(plaintext, key)
    else:
        print("CBC mode")
        return enc_AES_CBC(plaintext, key, iv=gen_AES_key())

def detect_ECB_or_CBC(enc_func):
    payload = b'A' * 100
    key = gen_AES_key()
    if find_repeated_ECB([enc_func(payload, key)]) is None:
        return "CBC"
    else:
        return "ECB"


def enc_AES_ECB_pad(plaintext, key):
    # Pad for ECB
    blocks = [plaintext[i:i+16] for i in range(0, len(plaintext), 16)]
    blocks[-1] = pkcs7_padding(blocks[-1], 16)
    plaintext = b''.join(blocks)

    return enc_AES_ECB(plaintext, key)

def ecb_byte_brute_decryption(enc_func, key):
    secret = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
    secret = hex2b(b642hex(secret))

    # Determine block size
    block_size = 0
    for i in range(1, 100):
        cur = len(enc_func(b'A' * i, key))
        next = len(enc_func(b'A' * (i+1), key))
        if (cur != next):
            block_size = next - cur
            print("Block size: " + str(block_size))
            break

    # Determine function type
    if detect_ECB_or_CBC(enc_func) == "ECB":
        print("ECB mode detected")

    dec_str = b''
    my_str = b'A' * (block_size - 1)
    block_num = 1 # Keeps track of how much of the ciphertext to match
    while(True): 
        mapping = {}
        for i in range(256): # Try all possibilities
            v = my_str + dec_str + bytes([i]) 
            k = enc_AES_ECB_pad(v, key)
            mapping[k] = v # Map the possible values to the unique enc
        enc = enc_AES_ECB_pad(my_str + secret, key)
        match = mapping[enc[:block_num*block_size]]
        dec_str += bytes([match[-1]])

        # We've fed the entire string to our decryptor
        if len(enc) == (block_num * block_size):
            break

        # Update
        if len(my_str) == 0:
            my_str = b'A' * (block_size - 1) # Pad the input again
            block_num += 1
        else:
            my_str = my_str[1:] # Remove the first letter

    print(dec_str)


