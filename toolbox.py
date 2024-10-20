from Crypto.Cipher import AES
from pwn import *
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
    # Prepare iat' and rat' by padding with 7 zero bits to make them 8 bits
    iat_int = int.from_bytes(iat, byteorder='big')  # Convert bytes to int
    rat_int = int.from_bytes(rat, byteorder='big')  # Convert bytes to int

    iat_prime = p8(iat_int & 0x01)  # Keep the least significant bit
    rat_prime = p8(rat_int & 0x01)  # Keep the least significant bit

    # Generate p1: pres || preq || rat' || iat'
    p1 = pres + preq + rat_prime + iat_prime
    p1_xor_r = XOR(p1, r)
    intermediate_result = e(k, p1_xor_r)
    p2 = padding + ia + ra
    final_input = XOR(intermediate_result, p2)
    confirm_value = e(k, final_input)

    return confirm_value

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
    # Extract the least significant 64 bits from r1 and r2
    r1_prime = r1[8:]  # Last 8 bytes (64 bits)
    r2_prime = r2[8:]  # Last 8 bytes (64 bits)

    # Concatenate r1' and r2' to form the 128-bit value r'
    r_prime = r1_prime + r2_prime

    # Encrypt r' using AES with key k to generate the STK
    stk = e(k, r_prime)
    return stk

def derive_session_key(skd_p, skd_c, ltk):
    skd = skd_p + skd_c
    cipher = AES.new(ltk, AES.MODE_ECB)
    return cipher.encrypt(skd)