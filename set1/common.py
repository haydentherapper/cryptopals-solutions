import binascii
import base64

def hex2b64(hex):
    bin_str = binascii.unhexlify(hex.encode())
    return base64.b64encode(bin_str).decode()

def b642hex(b64):
    bin_str = base64.b64decode(b64.encode())
    return binascii.hexlify(bin_str).decode()    

def fixed_xor(b_str1, b_str2):
    return bytes([x ^ y for x,y in zip(b_str1, b_str2)])
