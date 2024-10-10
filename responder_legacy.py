#!/usr/bin/env python3
import logging
import random
from pwn import *
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from toolbox import *

# !!! In byte strings, the most significant bit is on the right !!!

# Packet types
PAIR_REQ_OPCODE = 0x01
PAIR_RSP_OPCODE = 0x02
PAIR_CONFIRM_OPCODE = 0x03
PAIR_RANDOM_OPCODE = 0x04
PAIR_FAILED_OPCODE = 0x05
ENCRYPTED_DATA_OPCODE = 0x06

# IO Capabilities
IO_CAP_DISPLAY_ONLY = 0x00
IO_CAP_DISPLAY_YES_NO = 0x01
IO_CAP_KEYBOARD_ONLY = 0x02
IO_CAP_NO_INPUT_NO_OUTPUT = 0x03
IO_CAP_KEYBOARD_DISPLAY = 0x04

# Set the IO capabilities and authentication requirements
IOCap = IO_CAP_DISPLAY_ONLY  # Responder can display passkey
OOBDATA = 0x00  # OOB authentication data not present
AuthReq = 0x01  # MITM protection required
MAXKEYSIZE = 16
INITIATOR_KEY_DIST = 0x00
RESPONDER_KEY_DIST = 0x00
MAC_ADDR = b'\x22\x33\x44\x55\x66\x77'  # Responder's MAC address

iat = b'\x00'  # Initiator Address Type (Public)
rat = b'\x00'  # Responder Address Type (Public)

# Create and configure logger
logger = logging.getLogger('responder')
logger.setLevel(logging.DEBUG)  # Logger level

# Create console handler for INFO level
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console_handler.setFormatter(console_formatter)

# Add handlers to the logger
logger.addHandler(console_handler)

def start_passkey_entry_pairing(conn):
    try:
        # Exchange MAC addresses
        MAC_ADDR_initiator = conn.recv(6)
        logger.info(f'Received MAC: {MAC_ADDR_initiator.hex()}')

        conn.send(MAC_ADDR)
        logger.info(f'Sent MAC: {MAC_ADDR.hex()}')

        # Receive pairing request
        pair_req = conn.recv()
        logger.info(f'Received pairing request: {pair_req.hex()}')

        if pair_req[0] == PAIR_REQ_OPCODE:
            # Send pairing response
            pair_rsp_payload = p8(IOCap) + p8(OOBDATA) + p8(AuthReq) + \
                               p8(MAXKEYSIZE) + p8(INITIATOR_KEY_DIST) + p8(RESPONDER_KEY_DIST)
            pair_rsp = p8(PAIR_RSP_OPCODE) + pair_rsp_payload
            conn.send(pair_rsp)
            logger.info(f'Sent pairing response: {pair_rsp.hex()}')

            # Determine if Passkey Entry is supported
            # For simplicity, we proceed assuming Passkey Entry is agreed upon

            # Generate and display passkey
            passkey = random.randint(0, 999999)
            print(f"Passkey to enter on the initiator device: {passkey:06d}")

            # Derive Temporary Key (TK)
            TK = passkey.to_bytes(16, byteorder='little')

            # Generate random number (rand)
            LP_RAND_R = # TODO

            # Calculate Confirm Value (ConfirmValue)
            # pres and preq are the pairing response and request including the opcodes
            pres = pair_rsp  # 7 bytes
            preq = pair_req  # 7 bytes

            ConfirmValue = # TODO
            logger.debug(f'Computed ConfirmValue: {ConfirmValue.hex()}')

            # Receive ConfirmValue from initiator
            confirm_pkt = conn.recv()
            logger.info(f'Received ConfirmValue from initiator: {confirm_pkt.hex()}')

            if confirm_pkt[0] == PAIR_CONFIRM_OPCODE:
                ConfirmValue_initiator = confirm_pkt[1:]

                # Send ConfirmValue to initiator
                confirm_resp = p8(PAIR_CONFIRM_OPCODE) + ConfirmValue
                conn.send(confirm_resp)
                logger.info(f'Sent ConfirmValue: {confirm_resp.hex()}')

                # Receive rand_initiator from initiator
                rand_pkt = conn.recv()
                logger.info(f'Received rand_initiator: {rand_pkt.hex()}')

                if rand_pkt[0] == PAIR_RANDOM_OPCODE:
                    rand_initiator = rand_pkt[1:]

                    # Send LP_RAND_R to initiator
                    rand_resp = p8(PAIR_RANDOM_OPCODE) + LP_RAND_R
                    conn.send(rand_resp)
                    logger.info(f'Sent LP_RAND_R: {rand_resp.hex()}')

                    # Verify initiator's ConfirmValue
                    ConfirmValue_calc = # TODO
                    if ConfirmValue_calc != ConfirmValue_initiator:
                        logger.error("Confirm values do not match. Pairing failed.")
                        # Send Pairing Failed packet (if desired)
                        conn.send(p8(PAIR_FAILED_OPCODE))
                        conn.close()
                        return

                    # Generate Short-Term Key (STK)
                    STK = # TODO
                    logger.debug(f'Generated STK: {STK.hex()}')

                    # Encryption with STK can proceed here
                    # Receive IV_C and SKD_C from responder
                    ivskd_c = conn.recv()
                    log.info(f'Received IV_C + SKD_C:{ivskd_c.hex()}')
                    iv_c = ivskd_c[:4]
                    skd_c = ivskd_c[4:]

                    # Generate IV_P and SKD_P and send them to responder
                    iv_p = get_random_bytes(4)
                    skd_p = get_random_bytes(8)
                    conn.send(iv_p + skd_p)
                    log.info(f'Send IV_P + SKD_P:{iv_p.hex() + skd_p.hex()}')

                    session_iv = # TODO
                    session_key = # TODO

                    # Receive encrypted data from initiator
                    encrypted_data_pkt = conn.recv()
                    logger.info(f'Received encrypted data: {encrypted_data_pkt.hex()}')

                    if encrypted_data_pkt[0] == ENCRYPTED_DATA_OPCODE:
                        encrypted_data = encrypted_data_pkt[1:]
                        ciphertext = encrypted_data[:-4]  # Assuming 4-byte MAC
                        mac = encrypted_data[-4:]

                        # Decrypt using STK
                        cipher = AES.new(session_key, AES.MODE_CCM, nonce=session_iv, mac_len=4)
                        try:
                            plaintext = cipher.decrypt_and_verify(ciphertext, mac)
                            logger.info("Pairing successful. Data decrypted.")
                            print('Decrypted data:', plaintext)
                        except ValueError as e:
                            logger.error(f"Decryption failed: {e}")
                            conn.close()
                            return
                    else:
                        logger.error("Did not receive expected encrypted data packet.")
                        conn.close()
                        return

                else:
                    logger.error("Did not receive expected Pairing Random packet from initiator.")
                    conn.close()
                    return

            else:
                logger.error("Did not receive expected ConfirmValue from initiator.")
                conn.close()
                return

        else:
            logger.error("Did not receive expected Pairing Request packet.")
            conn.close()
            return

    except Exception as e:
        logger.error(f"An error occurred: {e}")
    finally:
        conn.close()
        logger.info("Connection closed.")

def start_server(host='127.0.0.1', port=65432):
    server = listen(port, bindaddr=host)
    logger.info(f'Server listening on {host}:{port}')

    connection = server.wait_for_connection()
    logger.info(f'Connected by {connection.rhost}:{connection.rport}')

    start_passkey_entry_pairing(connection)

if __name__ == "__main__":
    start_server()
