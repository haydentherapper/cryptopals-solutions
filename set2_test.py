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

def c13():
	assert(profile_for('foo&=') == profile_for('foo'))
	output = ecb_cut_and_paste()
	assert(output['role'] == 'admin')
	print("C13 passed!\n")

def c14():
	secret = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
	secret = hex2b(b642hex(secret))
	enc_func = enc_AES_ECB_pad
	key = gen_AES_key()
	print("Testing a prefix of block_size")
	prefix = b'A' * 16
	output = ecb_byte_brute_decryption_hard(enc_func, key, prefix)
	assert(output == secret)

	print("Testing a prefix of <block_size")
	prefix = b'A' * 5
	output = ecb_byte_brute_decryption_hard(enc_func, key, prefix)
	assert(output == secret)

	print("Testing a prefix of >block_size")
	prefix = b'A' * 35
	output = ecb_byte_brute_decryption_hard(enc_func, key, prefix)
	assert(output == secret)
	print("C14 passed!\n")

def c15():
	input = "ICE ICE BABY\x04\x04\x04\x04".encode()
	output = "ICE ICE BABY"
	c15_output = pkcs7_rm_padding(input)
	assert(output == c15_output.decode())

	input = "ICE ICE BABY\x05\x05\x05\x05".encode()
	try:
		pkcs7_rm_padding(input)
	except Exception:
		print("Caught exception for wrong number of bytes")

	input = "ICE ICE BABY\x01\x02\x03\x04".encode()
	try:
		pkcs7_rm_padding(input)
	except Exception:
		print("Caught exception for wrong padding bytes")
	print("C15 passed!\n")

def c16():
	injection_string = ";admin=true;".encode()
	ciphertext, key = cbc_bitflip(injection_string)
	result = dec_userdata(ciphertext, key)
	print("Confirming \"admin=true\" is in the plaintext")
	assert(result)
	print("C16 passed!\n")

if __name__ == '__main__':
    c9()
    c10()
    c11()
    c12()
    c13()
    c14()
    c15()
    c16()


