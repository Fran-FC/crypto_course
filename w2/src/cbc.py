import base64
from typing import Mapping
from Crypto.Cipher import AES
from Crypto import Random

test_plain_text = "This message is secret bro"

# given hex encoded string keys
k1 = bytes.fromhex('140b41b22a29beb4061bda66b6747e14')
k2 = bytes.fromhex('140b41b22a29beb4061bda66b6747e14')

def cbc_enc(m_i, iv_i, k):
    xor = bytes([_m ^ _iv for _m, _iv in zip(m_i, iv_i)])
    # chiper block
    aes = AES.new(
        k,
        AES.MODE_CBC,
        iv_i
    )
    c_i = aes.encrypt(xor)
    
    return c_i

def encrypt(msg, key):
    # generate random IV
    IV = Random.urandom(16) 

    # form plain_text with pad following the PKCS5 padding scheme
    pad_len = 16 - len(msg)%16
    if not pad_len > 0: 
        pad_len = 16
    pad = pad_len.to_bytes(1, "big")*pad_len
    msg = bytes(msg, 'utf-8') +pad
    
    c = b''
    for i in range(int(len(msg)/16)):
        m_i = msg[16*i:16*(i+1)]
        c_i = cbc_enc(m_i, IV, key) 
        
        c = c+c_i
    print(c)
    print(len(c))
    




    
    

def decrypt(cypher, key):
    pass

def main():
    action = encrypt
    action(test_plain_text, k1)






if __name__ == "__main__":
    main()
