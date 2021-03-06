from Crypto.Cipher import AES
from Crypto import Random
import operations

# given hex encoded string keys
k = bytes.fromhex('140b41b22a29beb4061bda66b6747e14')

c1 = bytes.fromhex('4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81')
c2 = bytes.fromhex('5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253')

def cbc_enc(m_i, iv_i, k):
    xor = bytes([_m ^ _iv for _m, _iv in zip(m_i, iv_i)])
    # chiper block
    aes = AES.new(k)
    c_i = aes.encrypt(xor)
    
    return c_i

def cbc_dec(c_i, iv_i, k):
    aes = AES.new(k)
    m_i = bytes([a ^ b for a, b in zip(iv_i, aes.decrypt(c_i))])
    
    return m_i

def encrypt(msg, key):
    # generate random IV
    IV = Random.urandom(16) 

    msg = operations.add_padding(16, msg)
    
    c = b''
    iv_i = IV
    for i in range(int(len(msg)/16)):
        m_i = msg[16*i:16*(i+1)]
        c_i = cbc_enc(m_i, iv_i, key) # encrypt
        
        iv_i = c_i # update IV
        c = c+c_i # add cypher block to final result
    # prepend IV
    c = IV+c

    return c
    

def decrypt(cypher, key):
    iv_i = cypher[0:16] # prepended IV firts 16 bytes
    cypher = cypher[16:len(cypher)]

    m = b''
    for i in range(int(len(cypher)/16)):
        c_i = cypher[16*i:16*(i+1)] # take blocks of 16 bytes
        m_i = cbc_dec(c_i, iv_i, key)
    
        iv_i = c_i 
        m = m+m_i
        
    return operations.remove_padding(m)

def main():
    print(decrypt(c1, k))
    print(decrypt(c2, k))
    
if __name__ == "__main__":
    main()
