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