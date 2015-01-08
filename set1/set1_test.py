from common import *
import binascii

def c1():
    input = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    output = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
    assert(hex2b64(input) == output)
    print("C1 passed!")

def c2():
    input = ('1c0111001f010100061a024b53535009181c', 
    '686974207468652062756c6c277320657965')
    output = '746865206b696420646f6e277420706c6179'    
    b_input = list(map(hex2b, input))
    c2_output = fixed_xor(b_input[0], b_input[1])
    assert(b2hex(c2_output).decode() == output)
    print("C2 passed!")

def c3():
    input = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'    
    print(byte_xor_cipher(hex2b(input)).decode())
    
if __name__ == '__main__':
    c1()
    c2()
    c3()
   
