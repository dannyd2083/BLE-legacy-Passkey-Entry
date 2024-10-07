from Crypto.Cipher import AES

# !!! In byte strings, the most significant bit is on the right !!!

def e(key, data):
    """
    Referred to as the security function e in the docs
    """
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(data)

def XOR(byte_string_a, byte_string_b):
    assert len(byte_string_a) == len(byte_string_b), "XORing different lengths; You don't seem to know what you're doing"
    return bytes(a ^ b for a, b in zip(byte_string_a, byte_string_b))

def c1(k, r, pres, preq, iat, ia, rat, ra, padding = b'\x00'*4):
    """
    k is 128 bits
    r is 128 bits
    pres is 56 bits
    preq is 56 bits
    iat is 1 bit - we assume iat is in byte string format
    ia is 48 bits
    rat is 1 bit - we assume iat is in byte string format
    ra is 48 bits
    padding is 32 zero bits
    In e, the most significant octet of key corresponds to key[0], the most significant octet of plaintextData corresponds to in[0] and the most significant octet of encryptedData corresponds to out[0].
    """
    #TODO: implement c1, return type should be bytes
    return b'\x00'

def s1(k, r1, r2):
    """
    k is 128 bits
    r1 is 128 bits
    r2 is 128 bits
    r1_prime = the_least_significant 64 bits of r1
    r2_prime = the_least_significant 64 bits of r2
    r_prime = r1_prime || r2_prime
    r_prime is used as plaintextData to security function e (i.e., AES_ECB)
    In e, the most significant octet of key corresponds to key[0], the most significant octet of plaintextData corresponds to in[0] and the most significant octet of encryptedData corresponds to out[0].
    """
    #TODO: implement s1, return type should be bytes
    return b'\x00'

def derive_session_key(skd_p, skd_c, ltk):
    skd = skd_p + skd_c
    cipher = AES.new(ltk, AES.MODE_ECB)
    return cipher.encrypt(skd)