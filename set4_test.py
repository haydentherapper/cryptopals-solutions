from crypto import *
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
    pass

if __name__ == '__main__':
    c25()
    c26()
