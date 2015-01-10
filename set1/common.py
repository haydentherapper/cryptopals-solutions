import binascii
import base64
import string, sys, math, itertools
from Crypto.Cipher import AES

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

def dec_aes(b_str, key):
    aes = AES.new(key, AES.MODE_ECB)
    return aes.decrypt(b_str)

def find_repeated_ecb(b_str_list):
    for data in b_str_list:
        blocks = [data[i:i+16] for i in range(0, len(data), 16)]
        if len(blocks) != len(set(blocks)):
            return data

