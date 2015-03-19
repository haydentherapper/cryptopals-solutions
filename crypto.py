import binascii
import base64
import string, sys, math, itertools
from Crypto.Cipher import AES
from Crypto import Random
from random import randint
import struct

import mt19937, time

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

SINGLE_LETTER_FREQS = {
    'e': .1202,
    't': .0910,
    'a': .0812,
    'o': .0768,
    'i': .0731,
    'n': .0695,
    's': .0628,
    'r': .0602,
    'h': .0592,
    'd': .0432,
    'l': .0398,
    'u': .0288,
    'c': .0271,
    'm': .0261,
    'f': .0230,
    'y': .0211,
    'w': .0209,
    'g': .0203,
    'p': .0182,
    'b': .0149,
    'v': .0111,
    'k': .0069,
    'x': .0017,
    'q': .0011,
    'j': .0010,
    'z': .0007
    }

BIGRAM_FREQS = {
    'th': .152,
    'he': .128,
    'in': .094,
    'er': .094,
    'an': .082,
    're': .068,
    'nd': .063,
    'at': .059,
    'on': .057,
    'nt': .056,
    'ha': .056,
    'es': .056,
    'st': .055,
    'en': .055,
    'ed': .053,
    'to': .052,
    'it': .050,
    'ou': .050,
    'ea': .047,
    'hi': .046,
    'is': .046,
    'or': .043,
    'ti': .034,
    'as': .033,
    'te': .027,
    'et': .019,  
    'ng': .018,
    'of': .016,
    'al': .009,
    'de': .009,
    'se': .008,
    'le': .008,
    'sa': .006,
    'si': .005,
    'ar': .004,
    've': .004,
    'ra': .004,
    'ld': .002,   
    'ur': .002
    }   

TRIGRAM_FREQS = {
    'the': .03508232,
    'and': .01593878,
    'ing': .01147042,
    'her': .00822444,
    'hat': .00650715,
    'his': .00596748,
    'tha': .00593593,
    'ere': .00560594,
    'for': .00555372,
    'ent': .00530771,
    'ion': .00506454,
    'ter': .00461099,
    'was': .00460487,
    'you': .00437213,
    'ith': .00431250,
    'ver': .00430732,
    'all': .00422758,
    'wit': .00397290,
    'thi': .00394796,
    'tio': .00378058
    }

QUADGRAM_FREQS = {
    'that': .00761242,
    'ther': .00604501,
    'with': .00573866,
    'tion': .00551919,
    'here': .00374549,
    'ould': .00369920,
    'ight': .00309440,
    'have': .00290544,
    'hich': .00284292,
    'whic': .00283826,
    'this': .00276333,
    'thin': .00270413,
    'they': .00262421,
    'atio': .00262386,
    'ever': .00260695,
    'from': .00258580,
    'ough': .00253447,
    'were': .00231089,
    'hing': .00229944,
    'ment': .00223347
    }

def score(i):
    def toChar(p):
        return ''.join(list(map(chr, p)))

    tot_score = 0
    input = i.lower()
    
    single_score = sum([SINGLE_LETTER_FREQS[chr(c)] \
            for c in input if chr(c) in SINGLE_LETTER_FREQS])

    pairs = [input[i:i+2] for i in range(0, len(input)-1)]
    bigram_score = sum([BIGRAM_FREQS[toChar(p)] \
            for p in pairs if toChar(p) in BIGRAM_FREQS])

    trios = [input[i:i+3] for i in range(0, len(input)-2)]
    trigram_score = sum([TRIGRAM_FREQS[toChar(t)] \
            for t in trios if toChar(t) in TRIGRAM_FREQS])

    quads = [input[i:i+4] for i in range(0, len(input)-3)]
    quadgram_score = sum([QUADGRAM_FREQS[toChar(q)] \
            for q in quads if toChar(q) in QUADGRAM_FREQS])

    return single_score + bigram_score + trigram_score + quadgram_score \
             - float(input.count(b'\x00') / len(input))

def byte_xor_cipher_with_key(b_str):
    max_score = -1
    message = ''
    key = b''
    for c in range(256):
        xor_str = bytes([c]) * len(b_str)
        dec = fixed_xor(b_str, xor_str)
        if score(dec) > max_score:
            max_score = score(dec)
            message = dec
            key = bytes([c])
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

    final_key = b''
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

def pkcs7_padding(b_str, pad_len=16):
    return b_str + \
        (chr(pad_len - len(b_str)) * (pad_len - len(b_str))).encode()

def pkcs7_rm_padding(b_str):
    last_byte = b_str[-1]
    if (last_byte <= len(b_str)):
        padding = b_str[-last_byte:]
        if (len(set(padding)) == 1):
            return b_str[:-last_byte]
        else:
            raise Exception("Bad padding")
    else:
        raise Exception("Incorrect final padding byte")

def enc_AES_CBC(plaintext, key, iv=bytes(16)):
    blocks = [plaintext[i:i+16] for i in range(0, len(plaintext), 16)]
    ciphertext = b''
    for i in range(len(blocks)):
        block = blocks[i]
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
    blocks[-1] = pkcs7_padding(blocks[-1])
    plaintext = b''.join(blocks)

    if randint(0,1) == 0:
        print("ECB mode")
        return enc_AES_ECB(plaintext, key)
    else:
        print("CBC mode")
        return enc_AES_CBC(plaintext, key, iv=gen_AES_key())

def detect_ECB_or_CBC(enc_func):
    payload = b'A' * 100
    blocks = [payload[i:i+16] for i in range(0, len(payload), 16)]
    blocks[-1] = pkcs7_padding(blocks[-1])
    payload = b''.join(blocks)

    key = gen_AES_key()
    if find_repeated_ECB([enc_func(payload, key)]) is None:
        return "CBC"
    else:
        return "ECB"

def enc_AES_ECB_pad(plaintext, key):
    # Pad for ECB
    blocks = [plaintext[i:i+16] for i in range(0, len(plaintext), 16)]
    blocks[-1] = pkcs7_padding(blocks[-1])
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
            k = enc_func(v, key)
            mapping[k] = v # Map the possible values to the unique enc
        enc = enc_func(my_str + secret, key)
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

    return dec_str

def key_value_parser(input):
     return dict([i.split("=") if i.count('=') > 0 else [i, ''] 
        for i in input.split("&")])

def profile_for(email):
    email = email.replace('=','').replace('&','')
    uid = 10
    role = 'user'
    return 'email=' + email + '&uid=' + str(uid) + '&role=' + role

def enc_user_profile(email, key):
    return enc_AES_ECB_pad(profile_for(email).encode(), key)
  
def dec_user_profile(b_str, key):
    return key_value_parser(dec_AES_ECB(b_str, key).decode())

def ecb_cut_and_paste():
    # |----------------|----------------|----------------|
    # |email=AAAAAAAAAA|AAA&uid=10&role=|user
    #                  |email=AAAAAAAAAA|admin&uid=10&rol|
    key = gen_AES_key()
    # First encryption generates user role
    block1_pad = 'A' * (16 - len("email="))
    block2_pad = 'A' * (16 - len("&uid=10&role="))
    email = block1_pad + block2_pad
    enc_str1 = enc_user_profile(email, key)

    # Second encryption generates admin role
    email = block1_pad + 'admin'
    enc_str2 = enc_user_profile(email, key)

    # Cut and paste 1st two blocks from 1 and 2nd block from 2
    cut_and_paste = enc_str1[:32] + enc_str2[16:32]

    return dec_user_profile(cut_and_paste, key)

# TODO: Possible second method: Continually add bytes until
# a repeated segment is found, so we then know alignment and
# know how many bytes need to be added for alignment
def ecb_byte_brute_decryption_hard(enc_func, key, prefix):
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

    # Determine offset with random prefix
    # Taking BLOCK_SIZE bytes and shifting them down one-by-one,
    # we are guarenteed to find a block with one of these chunks.
    # We then know the offset, and we know where the block is,
    # so we cut off the prefix and offset so we start with 'A'
    lookup = {}
    block = bytes([i for i in range(block_size)])
    for i in range(block_size):
        enc = enc_func(block, key)
        lookup[enc] = i
        block = block[1:] + bytes([block[0]]) # Shift 1st byte to the end
    
    cipher = enc_func(prefix + block + block + secret, key)
    c_blocks = [cipher[i:i+block_size] \
                for i in range(0, len(cipher), block_size)]
    padding_size = 0
    truncate_block_num = 0
    for i in range(len(c_blocks)):
        for k in lookup:
            if c_blocks[i] == k:
                padding_size = lookup[k] # Save the length of the pad
                truncate_block_num = i
                break

    # Add padding and index to truncate at
    new_prefix = b'Q' * padding_size
    truncation = truncate_block_num*block_size
    if padding_size % block_size == 0:
        truncation -= block_size # Truncate one less block
    
    dec_str = b''
    my_str = b'A' * (block_size - 1)
    block_num = 1 # Keeps track of how much of the ciphertext to match
    while(True): 
        mapping = {}
        for i in range(256): # Try all possibilities
            v = my_str + dec_str + bytes([i]) 
            k = enc_func(prefix + new_prefix + v, key)[truncation:]
            mapping[k] = v # Map the possible values to the unique enc
        enc = enc_func(prefix + new_prefix + my_str + secret, key)[truncation:]
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

    return dec_str

def take_userdata(input):
    input = input.replace(';', '').replace('=', '')
    input = ("comment1=cooking%20MCs;userdata=" + \
            input + \
            ";comment2=%20like%20a%20pound%20of%20bacon").encode()
    key = gen_AES_key()

    blocks = [input[i:i+16] for i in range(0, len(input), 16)]
    blocks[-1] = pkcs7_padding(blocks[-1])
    input = b''.join(blocks)

    return (enc_AES_CBC(input, key), key)

def dec_userdata(input, key):
    pt = dec_AES_CBC(input, key).decode(encoding='ISO-8859-1')
    mapping = dict([i.split("=") if i.count('=') > 0 else [i, ''] 
                    for i in pt.split(";")])
    return 'admin' in mapping and mapping['admin'] == 'true'

def cbc_bitflip(injection_string):
    # Output will contain ";admin=true;"
    some_output = "comment1=cooking%20MCs;userdata=".encode()
    second_output_block = some_output[16:]

    ciphertext, key = take_userdata('')
    ciphertext = bytearray(ciphertext) # To make it mutable

    # For any byte in the ith cipherblock, one can change a byte in
    # the (i+1)th cipherblock at the same index. 
    # plaintext[i] = X
    # ciphertext[i] = Y
    # desired_chr = Z
    # We know when decrypted, the byte will be X. Therefore, we XOR
    # to the ciphertext X to make this byte 0. We then XOR the
    # desired_chr Z, so Y = Y ^ X ^ Z, which results in Z when decrypted.
    for i, ch in enumerate(injection_string):
        ciphertext[i] = ciphertext[i] ^ \
                        second_output_block[i] ^ \
                        injection_string[i]
    ciphertext = bytes(ciphertext)
    return (ciphertext, key)

padding_oracle_key = gen_AES_key()

def enc_AES_CBC_oracle(plaintext):
    blocks = [plaintext[i:i+16] for i in range(0, len(plaintext), 16)]
    blocks[-1] = pkcs7_padding(blocks[-1])
    plaintext = b''.join(blocks)
    return enc_AES_CBC(plaintext, padding_oracle_key)

def dec_AES_CBC_oracle(ciphertext):
    plaintext = dec_AES_CBC(ciphertext, padding_oracle_key)
    try:
        blocks = [plaintext[i:i+16] for i in range(0, len(plaintext), 16)]
        blocks[-1] = pkcs7_rm_padding(blocks[-1])
        return True
    except Exception:
        return False

def change_block(iv, guess, pad_num, index, decrypted):
    xor_byte = pad_num ^ guess
    unmod_plus_new_change = iv[:index] + bytes([xor_byte ^ iv[index]])
    rest = b''.join([bytes([c1^c2^pad_num]) \
                for c1,c2 in zip(decrypted, iv[::-1])])   
    return unmod_plus_new_change + rest[::-1]

def padding_oracle_attack(ciphertext):
    final_decrypted = b''
    blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
    # Decrypt all but the first block, not knowing the IV
    for i in range(len(blocks)):
        block = blocks[i]
        if i != 0:
            prev_block = blocks[i-1]
        else:
            prev_block = bytes(16)
        decrypted = b''
        for byte in range(16): # For all bytes in block
            for guess in range(2, 256): # For every possible guess
                                        # Don't include 0x1 since 
                                        # xor'ing the pad_num with
                                        # the guess would cancel out,
                                        # leaving only the cipher
                modified_block = change_block(iv = prev_block, 
                                              guess = guess,
                                              pad_num = byte + 1,
                                              index = 15 - byte,
                                              decrypted = decrypted)
                m_blocks = modified_block + block
                result = dec_AES_CBC_oracle(m_blocks)
                if result:
                    decrypted += bytes([guess])
                    break
        final_decrypted += decrypted[::-1]
    return final_decrypted

def enc_AES_CTR(plaintext, key, nonce=0):
    blocks = [plaintext[i:i+16] for i in range(0, len(plaintext), 16)]
    ciphertext = b''
    counter = 0
    for block in blocks:
        # Combine the little endian unsigned nonce and counter
        data = struct.pack('<Q', nonce) + struct.pack('<q', counter)
        ciphertext += fixed_xor(enc_AES_ECB(data, key), block)
        counter += 1
    return ciphertext

def dec_AES_CTR(ciphertext, key, nonce=0):
    blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
    plaintext = b''
    counter = 0
    for block in blocks:
        # Combine the little endian unsigned nonce and counter
        data = struct.pack('<Q', nonce) + struct.pack('<q', counter)
        plaintext += fixed_xor(enc_AES_ECB(data, key), block)
        counter += 1
    return plaintext

# TODO: Do not truncate the texts, attempt to decrypt
# Having trouble with punctuation, need frequencies
def break_fixed_nonce_CTR(ciphertexts):
    keysize = len(min(ciphertexts, key=len))
    b_str = b''.join(c[:keysize] for c in ciphertexts)
    chunks = [b_str[i:i+keysize] \
            for i in range(0, len(b_str), keysize)]

    final_key = b''
    for i in range(len(max(chunks, key=len))):
        block = bytes([ch[i] for ch in chunks if i < len(ch)])
        final_key += byte_xor_cipher_with_key(block)[1]
    return [fixed_xor(cipher[:keysize], final_key).decode() \
                for cipher in ciphertexts]

def crack_mt19937_seed(seed):
    mt19937.init_generator(seed)
    target = mt19937.int32()

    now = int(time.time())
    i = 0
    while(True):
        mt19937.init_generator(now - i)
        if (mt19937.int32() == target):
            return (now - i)
        i += 1

def clone_mt19937(seed):
    mt19937.init_generator(seed)
    # Generate 624 values, primed from generate_numbers()
    target_values = [mt19937.int32() for i in range(624)]
    # Untemper all values, creating the intermediate mt array
    untempered_values = list(map(mt19937.untemper, target_values))
    # Splice the mt array in
    mt19937.mt = untempered_values
    # Do not regenerate the internal state, simply get 624 values
    new_target_values = [mt19937.int32_no_gen() for i in range(624)]
    # PRNG is now cloned and can predict values
    return target_values, new_target_values

def stream_cipher_mt19937(plaintext, seed):
    mt19937.init_generator(seed)
    ciphertext = b''
    for p in plaintext:
        c = p ^ (mt19937.int32() & 0xff)
        ciphertext += bytes([c])
    return ciphertext

def crack_mt19937_seed_cipher(ciphertext):
    plaintext = b'A' * len(ciphertext)
    for i in range(0xffff):
        enc_pt = stream_cipher_mt19937(plaintext, i)
        if ciphertext[-14:] == enc_pt[-14:]:
            return i

# Assumes the newtext is no longer than the ciphertext
# Hides key from user
def edit(ciphertext, key, offset, newtext):
    pt = dec_AES_CTR(ciphertext, key) # Properly, should do block length slices
    new_pt = pt[:offset] + newtext + pt[offset+len(newtext):]
    return enc_AES_CTR(new_pt, key)

def take_userdata_ctr(input):
    input = input.replace(';', '').replace('=', '')
    input = ("comment1=cooking%20MCs;userdata=" + \
            input + \
            ";comment2=%20like%20a%20pound%20of%20bacon").encode()
    key = gen_AES_key()

    return (dec_AES_CTR(input, key), key)

def dec_userdata_ctr(input, key):
    pt = dec_AES_CTR(input, key).decode(encoding='ISO-8859-1')
    mapping = dict([i.split("=") if i.count('=') > 0 else [i, ''] 
                    for i in pt.split(";")])
    return 'admin' in mapping and mapping['admin'] == 'true'

def ctr_bitflip(injection_string):
    # Output will contain "admin=true;" in first block
    some_output = "comment1=cooking%20MCs;userdata=".encode()
    ciphertext, key = take_userdata_ctr('')
    ciphertext = bytearray(ciphertext) # To make it mutable

    # For any byte in the ith cipherblock, one can change a byte in
    # the ith cipherblock at the same index. 
    # plaintext[i] = X
    # ciphertext[i] = Y
    # desired_chr = Z
    # We know when decrypted, the byte will be X. Therefore, we XOR
    # to the ciphertext X to make this byte 0. We then XOR the
    # desired_chr Z, so Y = Y ^ X ^ Z, which results in Z when decrypted.
    for i, ch in enumerate(injection_string):
        ciphertext[i] = ciphertext[i] ^ \
                        some_output[i] ^ \
                        injection_string[i]
    ciphertext = bytes(ciphertext)
    return (ciphertext, key)


