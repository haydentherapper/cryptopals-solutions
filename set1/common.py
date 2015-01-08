import binascii
import base64
import string, sys

def hex2b(hex):
    return binascii.unhexlify(hex)
    
def b2hex(b):
    return binascii.hexlify(b)

def hex2b64(hex):
    bin_str = binascii.unhexlify(hex.encode())
    return base64.b64encode(bin_str).decode()

def b642hex(b64):
    bin_str = base64.b64decode(b64.encode())
    return binascii.hexlify(bin_str).decode()    

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
    for c in string.ascii_uppercase:
        l_score = abs((float(input.count(c.encode()) / len(input)))-get_freq(c))
        tot_score += l_score
    
    percent_letters = list(filter(lambda x: ord(b'A') <= x <= ord('Z') 
    or x == ord(' '), input))
    return (1 - tot_score) + float(len(percent_letters) / len(input))

def byte_xor_cipher(b_str):
    max_score = 0
    message = ''
    for c in range(256):
        xor_str = chr(c).encode() * len(b_str)
        dec = fixed_xor(b_str, xor_str)
        if score(dec) > max_score:
            max_score = score(dec)
            message = dec
    return message
    
def detect_xor():
    max_score = 0
    message = ''
    for line in open('c4text.txt'):
        line = line.strip()
        dec = byte_xor_cipher(hex2b(line))
        if score(dec) > max_score:
            max_score = score(dec)
            message = line
    return message
