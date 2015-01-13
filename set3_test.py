from crypto import *
import random

def c17():
    strings = """MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
                MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
                MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
                MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
                MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
                MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
                MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
                MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
                MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
                MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93""".split()
    str = random.choice(strings)
    plaintext = hex2b(b642hex(str))
    ciphertext = enc_AES_CBC_oracle(plaintext)
    result = padding_oracle_attack(ciphertext)
    
    blocks = [plaintext[i:i+16] for i in range(0, len(plaintext), 16)]
    blocks[-1] = pkcs7_padding(blocks[-1])
    plaintext = b''.join(blocks)
    assert(result == plaintext)
    print("C17 passed!\n")

if __name__ == '__main__':
    c17()
