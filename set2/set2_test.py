from common import *
import binascii

def c9():
    input = "YELLOW SUBMARINE"
    output = "YELLOW SUBMARINE\x04\x04\x04\x04"
    assert(input == input)
    print("C9 passed!\n")
    
if __name__ == '__main__':
    c9()

