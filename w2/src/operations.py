def xor_bytes(a, b):
    xor = bytes([_m ^ _iv for _m, _iv in zip(a, b)])
    return xor

def add_padding(size, msg):
    # form plain_text with pad following the PKCS5 padding scheme
    pad_len = size - len(msg)%size
    if not pad_len > 0: 
        pad_len = size
    pad = pad_len.to_bytes(1, "big")*pad_len
    msg = bytes(msg, 'utf-8') +pad
    
    return msg

def remove_padding(msg):
    pad_len = msg[len(msg)-1] # read last byte to know padding size
    msg = msg[0:len(msg)-pad_len] # remove padding
    
    return msg