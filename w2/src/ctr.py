import operations
from Crypto.Cipher import AES
from Crypto import Random


k = bytes.fromhex('36f18357be4dbd77f050515c73fcf9f2')

c1 = bytes.fromhex('69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329')
c2 = bytes.fromhex('770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451')

def prf(k, iv):
    aes = AES.new(k)
    return aes.encrypt(iv)

def encrypt(msg, key):
    IV = Random.urandom(16)
    
    c = b''
    num_blocks = int(len(msg)/16)
    iv_i = IV
    for i in range(num_blocks):
        m_i = msg[16*i:16*(i+1)]
        f_i = prf(key, iv_i)

        c_i = operations.xor_bytes(m_i, f_i)  
        # add + 1 to IV
        iv_i = (int.from_bytes(iv_i, 'big')+1).to_bytes(16, 'big')
        c = c + c_i
        
    c = IV + c
    return c

def decrypt(cypher, key):
    iv_i = cypher[0:16]
    cypher = cypher[16:len(cypher)]
    
    m = b''
    num_blocks = int(len(cypher)/16) + (len(cypher)%16>0)
    for i in range(num_blocks):
        c_i = cypher[16*i:16*(i+1)]
        f_i = prf(key, iv_i)
        m_i = operations.xor_bytes(c_i, f_i)  
        iv_i = (int.from_bytes(iv_i, 'big')+1).to_bytes(16, 'big')
        m = m + m_i

    return m


def main():         
    print(decrypt(c1, k))
    print(decrypt(c2, k))


if __name__ == "__main__":
    main()