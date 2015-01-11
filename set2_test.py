from crypto import *
import binascii

def c9():
    input = "YELLOW SUBMARINE"
    output = "YELLOW SUBMARINE\x04\x04\x04\x04"
    assert(pkcs7_padding(input.encode(), pad_len=20) == output.encode())
    print("C9 passed!\n")
    
def c10():
	input = "YELLOW SUBMARINE"
	key = gen_AES_key()
	ciphertext = enc_AES_CBC(input.encode(), key)
	plaintext = dec_AES_CBC(ciphertext, key)
	assert(input == plaintext.decode())

	input = "HELLO WORLD"
	key = gen_AES_key()
	ciphertext = enc_AES_CBC(pkcs7_padding(input.encode()), key)
	plaintext = dec_AES_CBC(ciphertext, key)
	assert(input == pkcs7_rm_padding(plaintext).decode())
	print("C10 passed!\n")

def c11():
	enc_func1 = enc_AES_ECB
	enc_func2 = enc_AES_CBC
	assert(detect_ECB_or_CBC(enc_func1) == 'ECB')
	assert(detect_ECB_or_CBC(enc_func2) == 'CBC')
	print("C11 passed!\n")

def c12():
	secret = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
	secret = hex2b(b642hex(secret))
	enc_func = enc_AES_ECB_pad
	key = gen_AES_key()
	output = ecb_byte_brute_decryption(enc_func, key)
	print("Secret is...")
	print(output.decode())
	assert(output == secret)
	print("C12 passed!\n")

if __name__ == '__main__':
    c9()
    c10()
    c11()
    c12()


