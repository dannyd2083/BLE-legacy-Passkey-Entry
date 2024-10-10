#!/usr/bin/env python3
import logging
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
IOCap = IO_CAP_KEYBOARD_ONLY  # Initiator can input passkey
OOBDATA = 0x00  # OOB authentication data not present
AuthReq = 0x01  # MITM protection required
MAXKEYSIZE = 16
INITIATOR_KEY_DIST = 0x00
RESPONDER_KEY_DIST = 0x00
MAC_ADDR = b'\x11\x22\x33\x44\x55\x66'  # Initiator's MAC address
# Long Term Key
LTK = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'

iat = b'\x00'  # Initiator Address Type (Public)
rat = b'\x00'  # Responder Address Type (Public)

# Create and configure logger
logger = logging.getLogger('initiator')
logger.setLevel(logging.DEBUG)  # Logger level

# Create console handler for INFO level
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console_handler.setFormatter(console_formatter)

# Add handlers to the logger
logger.addHandler(console_handler)

def start_passkey_entry_pairing(host='127.0.0.1', port=65433):
    conn = remote(host, port)
    logger.info(f'Connected to server at {host}:{port}')

    try:
        # Exchange MAC addresses
        conn.send(MAC_ADDR)
        logger.info(f'Sent MAC: {MAC_ADDR.hex()}')

        MAC_ADDR_responder = conn.recv(6)
        logger.info(f'Received MAC: {MAC_ADDR_responder.hex()}')

        # Send pairing request to responder

        pair_req = # TODO
        conn.send(pair_req)
        logger.info(f'Sent pairing request: {pair_req.hex()}')

        # Receive pairing response
        pair_rsp = conn.recv()
        logger.info(f'Received pairing response: {pair_rsp.hex()}')

        if pair_rsp[0] == PAIR_RSP_OPCODE:
            # Determine if Passkey Entry is supported
            # For simplicity, we proceed assuming Passkey Entry is agreed upon

            # Prompt user to enter the passkey displayed on the responder device
            passkey_input = int(input("Enter the 6-digit passkey displayed on the responder device: "))
            if not 0 <= passkey_input <= 999999:
                raise ValueError("Invalid passkey. Must be a 6-digit number.")

            # Derive Temporary Key (TK)
            # TK is 128-bit (16 bytes), passkey is placed in least significant 16 bits (2 bytes)
            TK = passkey_input.to_bytes(16, byteorder='little')

            # Generate random number (rand)
            LP_RAND_I = # TODO

            # Calculate Confirm Value (LP_CONFIRM_I)
            # pres and preq are the pairing response and request including the opcodes
            pres = pair_rsp  # 7 bytes
            preq = pair_req  # 7 bytes

            LP_CONFIRM_I = # TODO
            logger.debug(f'Computed LP_CONFIRM_I: {LP_CONFIRM_I.hex()}')

            # Send LP_CONFIRM_I to responder
            confirm_pkt = p8(PAIR_CONFIRM_OPCODE) + LP_CONFIRM_I
            conn.send(confirm_pkt)
            logger.info(f'Sent LP_CONFIRM_I: {confirm_pkt.hex()}')

            # Receive LP_CONFIRM_I from responder
            confirm_resp = conn.recv()
            logger.info(f'Received LP_CONFIRM_I from responder: {confirm_resp.hex()}')

            if confirm_resp[0] == PAIR_CONFIRM_OPCODE:
                ConfirmValue_responder = confirm_resp[1:]

                # Send LP_RAND_I to responder
                rand_pkt = # TODO
                conn.send(rand_pkt)
                logger.info(f'Sent LP_RAND_I: {rand_pkt.hex()}')

                # Receive rand_responder from responder
                rand_resp = conn.recv()
                logger.info(f'Received rand_responder: {rand_resp.hex()}')

                if rand_resp[0] == PAIR_RANDOM_OPCODE:
                    rand_responder = rand_resp[1:]

                    # Verify responder's ConfirmValue
                    ConfirmValue_calc = # TODO
                    if ConfirmValue_calc != ConfirmValue_responder:
                        logger.error("Confirm values do not match. Pairing failed.")
                        # Send Pairing Failed packet (if desired)
                        conn.send(p8(PAIR_FAILED_OPCODE))
                        conn.close()
                        return

                    # Generate Short-Term Key (STK)
                    STK = # TODO
                    logger.debug(f'Generated STK: {STK.hex()}')

                    # Encryption with STK can proceed here
                    # For demonstration, we'll encrypt LTK and send it

                    # Encrypt LTK using STK (use AES-128 in CCM mode)
                    # Generate IV_C and SKD_C and send them to responder
                    iv_c = get_random_bytes(4)
                    skd_c = get_random_bytes(8)
                    conn.send(iv_c + skd_c)
                    log.info(f'Send IV_C + SKD_C:{iv_c.hex() + skd_c.hex()}')

                    # Receive IV_P and SKD_P from responder
                    ivskd_p = conn.recv()
                    log.info(f'Received IV_P + SKD_P:{ivskd_p.hex()}')

                    session_iv = # TODO
                    session_key = # TODO

                    cipher = AES.new(session_key, AES.MODE_CCM, nonce=session_iv, mac_len=4)
                    ciphertext, mac = cipher.encrypt_and_digest(LTK)
                    encrypted_data_pkt = p8(ENCRYPTED_DATA_OPCODE) + ciphertext + mac
                    conn.send(encrypted_data_pkt)
                    logger.info(f'Sent encrypted LTK: {encrypted_data_pkt.hex()}')

                    logger.info("Pairing successful. Data encrypted and sent.")

                else:
                    logger.error("Did not receive expected Pairing Random packet from responder.")
                    conn.close()
                    return
            else:
                logger.error("Did not receive expected LP_CONFIRM_I from responder.")
                conn.close()
                return

        else:
            logger.error("Did not receive expected Pairing Response packet.")
            conn.close()
            return

    except Exception as e:
        logger.error(f"An error occurred: {e}")
    finally:
        conn.close()
        logger.info("Connection closed.")

if __name__ == "__main__":
    start_passkey_entry_pairing()
