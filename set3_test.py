from crypto import *
import mt19937
import random, time

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

def c18():
    str = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
    input = hex2b(b642hex(str))
    output = b"Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "
    key = b"YELLOW SUBMARINE"
    plaintext = dec_AES_CTR(input, key)
    assert(output == plaintext)
    assert(enc_AES_CTR(plaintext, key) == input)
    print("C18 passed!\n")

def c19():
    input = [hex2b(b642hex(line.strip())) \
                for line in open('texts/c19text.txt', 'r')]
    key = gen_AES_key()
    input = list(map(lambda x: enc_AES_CTR(x, key), input))
    print('Decrypting c19...')
    output = break_fixed_nonce_CTR(input)
    for text in output:
        print(text)
    print("C19 passed! (May need to tweak some decryptions)\n")

def c20():
    input = [hex2b(b642hex(line.strip())) \
                for line in open('texts/c20text.txt', 'r')]
    key = gen_AES_key()
    input = list(map(lambda x: enc_AES_CTR(x, key), input))
    break_fixed_nonce_CTR(input)
    print('Decrypting c20...')
    output = break_fixed_nonce_CTR(input)
    for text in output:
        print(text)
    print("C20 passed! (May need to tweak some decryptions)\n")

def c21():
    seed = 1000
    mt19937.init_generator(seed)
    i = mt19937.int32()
    j = mt19937.int32()

    mt19937.init_generator(seed)
    assert(mt19937.int32() == i)
    assert(mt19937.int32() == j)
    print("C21 passed!\n")

def c22():
    now = int(time.time())
    seed = now - random.randint(40, 10000)
    print("Attempting to crack PRNG seeded with time...")
    result = crack_mt19937_seed(seed)
    assert(seed == result)
    print("The seed was: " + str(result))
    print("C22 passed!\n")

if __name__ == '__main__':
    c17()
    c18()
    c19()
    c20()
    c21()
    c22()
