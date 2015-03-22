from flask import Flask, request
from hashlib import sha1
from Crypto import Random
import binascii, time
import logging
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)
app = Flask(__name__)
KEY = Random.new().read(16)

def hmac_sha1(key, msg):  
    trans_5C = bytearray((x ^ 0x5c) for x in range(256))
    trans_36 = bytearray((x ^ 0x36) for x in range(256))
    blocksize = sha1().block_size # 64
    if len(key) > blocksize:
        key = sha1(key).digest()
    key = key + bytearray(blocksize - len(key))
    o_key_pad = key.translate(trans_5C)
    i_key_pad = key.translate(trans_36)
    return sha1(o_key_pad + sha1(i_key_pad + msg).digest())

def insecure_compare(m1, m2):
    for c1,c2 in zip(m1, m2):
        if c1 != c2:
            return False
        time.sleep(0.01)
    return True

def verify_mac(key, filename, signature):
    mac = hmac_sha1(key, filename).digest()
    if insecure_compare(mac, signature):
        return 200 if len(mac) == len(signature) else 500
    else:
        return 500

@app.route("/test", methods=['GET'])
def test():
    file = request.args.get('file').encode()
    signature = request.args.get('signature')
    signature = binascii.unhexlify(signature)
    result = verify_mac(KEY, file, signature)    
    if result == 200:
        return 'Good work!', 200
    else:
        return 'Bad MAC', 500

if __name__ == "__main__":
    print(binascii.hexlify(hmac_sha1(KEY, b'foobar').digest()))
    app.run()
