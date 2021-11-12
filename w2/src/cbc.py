from Crypto.Cipher import AES
from Crypto import Random

test_plain_text = "In this segment we're gonna look at another method to achieve chosen plain\
text security that's actually superior to CBC. And this method is called randomized          \
counter mode. Unlike CBC. Randomized counter mode uses a secure PRF. It doesn't              \
need a block cypher. It's enough for counter mode to just use a PRF because                  \
we're never going to be inverting this function F. So we're going to let F be the            \
secure PRF and it acts on N byte blocks. Again if we use AES, N will be 128. And             \
the way the encryption algorithm works in counter mode is it starts off by choosing          \
a random IV, that's 128 bytes random IV in the case of AES, and the essentially we           \
start counting. From this random IV, so you notice the first encryption is of IV             \
then IV+1 up to IV+L. So we generate this random pad. We XOR the result with the             \
message, and that gives us the cipher text. And, as usual, you notice that the               \
IV here is included along with the cipher text. So that, in fact, the cipher text is         \
a little longer than the original plain text. And the point, of course, is that,             \
encryption algorithm chooses a new IV for every message. And so even if I encrypt            \
the same message twice, I'm gonna get different resulting cipher texts. One                  \
thing to notice that this mode is completely paralyzable, unlike CBC. CBC                    \
was sequential. In other words, you couldn't encrypt block #5 until you've                   \
encrypted blocks ##1 to 4, so hardware companies who might have multiple                     \
AES engines working in parallel cannot actually use those AES engines when using             \
CBC because CBCs inherently sequential. So even though you might have two or three of        \
four AES engines, you could only use one of them when doing CBC encryption. With             \
counter mode, everything is completely paralyzable. If you have three AES engines            \
encryption basically will "

# given hex encoded string keys
k1 = bytes.fromhex('140b41b22a29beb4061bda66b6747e14')
k2 = bytes.fromhex('140b41b22a29beb4061bda66b6747e14')

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

    # form plain_text with pad following the PKCS5 padding scheme
    pad_len = 16 - len(msg)%16
    if not pad_len > 0: 
        pad_len = 16
    pad = pad_len.to_bytes(1, "big")*pad_len
    msg = bytes(msg, 'utf-8') +pad
    
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
    IV = cypher[0:16] # prepended IV firts 16 bytes
    cypher = cypher[16:len(cypher)]

    m = b''
    iv_i = IV 
    for i in range(int(len(cypher)/16)):
        c_i = cypher[16*i:16*(i+1)] # take blocks of 16 bytes
        m_i = cbc_dec(c_i, iv_i, key)
    
        iv_i = c_i 
        m = m+m_i
        
    
    pad_len = m[len(m)-1] # read last byte to know padding size
    m = m[0:len(m)-pad_len] # remove padding
    return m

def main():
    print(decrypt(encrypt(test_plain_text, k1), k1))
if __name__ == "__main__":
    main()
