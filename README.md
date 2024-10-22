# CMPT789 Assignment 2

After Assignment 1, you now have an idea of how Bluetooth Low Energy (BLE) pairing works at the high level.

This assignment aims to take one step further, to implement another pairing method of BLE and an attack against it.
To make it easy to implement and debug, the current pairing process is implemented on top of TCP rather than Bluetooth.

There are five files (excluding this one) in this repo, *initiator.py*, *responder.py*, *attacker.py*, *toolbox.py*, and *requirements.txt*.

The *initiator.py* implements the pairing logic on the *central* device side while the *responder.py* implements the pairing logic on the *peripheral* device side.

*toolbox.py* contains shared cryptographic functions.

*attacker.py* will be explained later.

In the following of this document, *initiator* indicates the *central* device and *responder* refers to the *peripheral* device.
(For those who are not familiar with those two roles, the *central* device is usually the smartphone and the *peripheral* device is usually the low-end BLE device, e.g., a smartlock.)

The pairing process starts from the initiator device sending out a *pairing request* to the responder device, which is already implemented in the *initiator.py* file.
Your overall goal is to implement the legacy Passkey Entry pairing of BLE and then implement an attack against this pairing process.

To implement the Passkey Entry pairing process, you may need to read the Bluetooth specification to understand how the pairing works.
The pairing process is described in [Volume 3: Host, Part H. Security Manager Specification](https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-54/out/en/host/security-manager-specification.html).

You only need to implement the **legacy Passkey Entry** pairing of BLE.

After you've finished the implementation, it's helpful to test your code with [Sample data of *c1()* and *s1()* functions](https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-54/out/en/host/security-manager-specification.html#UUID-24e06a05-2f0b-e5c9-7c65-25827ddb9975) to check if your implementation is correct or not.


## Task 0: Environment setup

This project is implemented in python3. The code is tested with python 3.12.3. You may use other versions of python as long as it's compatible with the two dependencies in *requiremnts.txt*.

You can use the following command to install the dependencies:
```
pip pwntools==4.13.0 pycryptodome==3.20.0
```

It's recommended to use a [virtual environment](https://docs.python.org/3/library/venv.html) for this project.
You can also use [virtualenvwrapper](https://virtualenvwrapper.readthedocs.io/en/latest/) to help manage the virual environments.

## Task 1: Implement the legacy Passkey Entry pairing in BLE (30 points)

The legacy Passkey Entry pairing method is used when one device has output capabilities (e.g., screen) and another device has input capabilities (e.g., keyboard).
For example, a laptop pairs with a Bluetooth keyboard.
So the IO capabilities of the initiator is *IO_CAP_KEYBOARD_ONLY* while the IO capabilities of the responder is *IO_CAP_DISPLAY_ONLY*.

This legacy pairing method is used when pairing with legacy devices, where new pairing methods are not available.

**Note that this pairing method is broken and should not be used when new pairing methods are available.**


Similar to the Just Works pairing method, there are also 3 phases in pairing (as shown in the following figure):
<img src="./figures/overall.png" alt="drawing" width="600"/>

### Phase 1: Pairing Feature Exchange

The initiator and responder first exchange their MAC addresses, followed by exchanging their pairing features.

Note that the optional step, **Security_Request**, in the previous figure is not needed in this project.
But before the initiator sends a **Pairing_Request**, the initiator should first send its MAC address and receive the responder's MAC address.

### Phase 2: LE legacy Passkey Entry pairing

In this phase, the two devices generate the Short Term Key (STK), as shown in the following figure:
<img src="./figures/legacy-phase2.png" alt="drawing" width="600"/>

In this phase, the *responder* will output a 6-digit random number to the screen and the user needs to input this number to the *initiator*.

Please read the specification to find all the details you need to implement.

### Phase 3: Distribute LTK (Long Term Key)

After Phase 2, the **LTK (Long Term Key)** will be encrypted (using STK) and distributed to the responder by the initiator.
*EDIV* and *Rand* can be ignored for now.

Please refer to [2.4.4.1. Encryption setup using STK](https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-54/out/en/host/security-manager-specification.html#UUID-8cd2df30-90dd-060d-4612-792ccace362f) to check out how encryption is performed using STK.

Use this formula to derive the session key:
```
session_key = AES_ECB(LTK, SKD)
```

Once the session key and session nonce are ready, use them to encrypt the LTK based on **AES_CCM** encryption and send the encrypted LTK to the responder.
The responder should be able to decrypt the message.

## Task 2: Implementation the sniff attack against this pairing process (50 points)

There is a significant weakness within this pairing method.

Assume the attacker is able to sniff all data exchanged between the initiator and the responder, as implemented in the *sniff()* function in *attacker.py*.

Finish the *attack()* function to launch the attack against this pairing method.

The goal of this attack is to obtain the LTK in plaintext.

**Please do not change the host address and the port number.**

## Task 3: Write a report (20 points)

Write a report explaining the following points:

- How each of the legacy pairing phases are implemented in your code? (5 points)

- What is the weakness in the legacy pairing method and how to exploit it? (15 points)

You can also include other topics you think are important for this project.

# Report for A2 CMPT789

## 1. Legacy Pairing Phases Implementation (5 Points)

### Phase 1: Feature Exchange
In this phase, the initiator sends a pairing request containing its supported features.

**Implementation:**
- The `initiator_legacy.py` sends the pairing request via the `send(pairing_request)` function.
- The responder replies with a pairing response containing its capabilities.
- Both sides store these exchanged features to decide the pairing method.

### Phase 2: Short-Term Key (STK) Generation
The STK is generated using the user-entered passkey and two random values from both initiator and responder.

**Implementation:**
- A 6-digit passkey is entered at the initiator side.
- The random values (`LP_RAND_I` and `LP_RAND_R`) are exchanged between the two devices.
- The `c1()` function generates the confirm values using the passkey and exchanged random values.
- If the confirm values match on both sides, the `s1()` function computes the STK using the passkey and random numbers.

### Phase 3: Session Key and Encryption Setup
The STK is used to derive a session key, which encrypts the communication link.

**Implementation:**
- The initiator and responder generate the `ivskd_c` and `ivskd_p` values and exchange them.
- `iv_p` and `iv_c` are extracted, combined, and encrypted with the STK to derive the session key on both sides.
- The session key encrypts the Long-Term Key (LTK), which is sent across the link using AES-CCM encryption.

---

## 2. Weakness in the Legacy Pairing Method and Exploitation (15 Points)

The Passkey Entry pairing method is vulnerable to brute force attacks due to:

- The passkey being only 6 digits long (000000 to 999999).
- A small keyspace (1 million possibilities) making brute force feasible.
- No secure channel used during pairing, allowing attackers to sniff the data exchanged between the initiator and responder.

### Exploitation Strategy

An attacker can perform a **man-in-the-middle (MITM)** attack by intercepting communication between the two devices, capturing:

- Pairing requests and responses
- Random values (`LP_RAND_I` and `LP_RAND_R`)
- Confirm values (`LP_CONFIRM_I` and `LP_CONFIRM_R`)

#### Steps for Exploitation:

1. **Sniffing Communication:**
   - The `sniff()` function intercepts data between the initiator and responder, including MAC addresses, pairing requests/responses, confirm values, and random values.

2. **Brute Force Attack:**
   - The `attack()` function iterates over all possible 6-digit passkeys (000000 to 999999).
   - For each passkey, it recomputes the confirm values using `c1()` and checks if they match the intercepted confirm values.
   - If a match is found, the correct passkey is identified.

3. **Session Key Derivation:**
   - Using the correct passkey, the STK is generated with the `s1()` function.
   - The session key is derived by combining `ivskd_c` and `ivskd_p` and encrypting them with the STK.

4. **Decryption:**
   - The encrypted LTK is decrypted using the derived session key to demonstrate how communication can be compromised.

---

## 3. Other Important Aspects

### Recommended Mitigations
- Use longer passkeys or stronger authentication methods.
- Encrypt the pairing process to prevent sniffing.
- Implement rate limiting on failed pairing attempts to prevent brute force attacks.
