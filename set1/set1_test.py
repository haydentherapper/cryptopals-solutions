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
    output = "Cooking MC's like a pound of bacon"
    c3_output = byte_xor_cipher(hex2b(input)).decode()
    assert(output == c3_output)
    print("C3 passed!")

def c4():
    output = "Now that the party is jumping\n"
    s = detect_xor()
    c4_output = byte_xor_cipher(hex2b(s)).decode()    
    assert(output == c4_output)
    print("C4 passed!")

def c5():
    input = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    output = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    
    key = "ICE"
    c5_output = repeating_key_xor(input.encode(), key.encode())
    assert(b2hex(c5_output) == output.encode())
    print("C5 passed!")
    
def c6():
    with open('c6text.txt', 'r') as file:
        data = file.read()
    input = hex2b(b642hex(data))
    output = "Terminator X: Bring the noise"    
    
    c6_output = find_repeating_xor_key(input)
    assert(output == c6_output)    
    print("C6 passed!")

if __name__ == '__main__':
    c1()
    c2()
    c3()
    c4()
    c5()
    c6()
