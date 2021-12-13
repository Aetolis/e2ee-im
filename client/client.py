import sys
import time
import base64
import hashlib
import os.path
import socketio
import ecdsa.util

from Crypto.Cipher import AES
from ecdsa import SigningKey, VerifyingKey, SECP256k1
from ecc import Secp256r1

flag = False
# shared_key = None

ecc = Secp256r1()


def read_keypair():
    """Reads a keypair from a file."""
    if os.path.exists("user.key"):
        with open("user.key", "rb") as f:
            data = f.read()
            privKey, pubKey_c = base64.b64decode(data).decode("ASCII").split(",")
        return int(privKey, 16), pubKey_c
    # If file does not exist, generate keypair
    privKey, pubKey_c = ecc.generate_keypair()
    with open("user.key", "wb") as f:
        # print(base64.b64encode(f"{hex(privKey)},{pubKey_c}".encode("ASCII")))
        f.write(base64.b64encode(f"{hex(privKey)},{pubKey_c}".encode("ASCII")))
    return privKey, pubKey_c


# Read or generate keypair
privKey, pubKey_c = read_keypair()

# Create a socketio client
sio = socketio.Client()


@sio.event
def connect():
    print("Client SID: ", sio.get_sid())

    # print("rand", rand_buf)
    # sig = ecc.sign(privKey, rand_buf)
    # print("sig:", sig)
    # sio.emit("response_sig", {"sig": sig, "pubKey_c": pubKey_c})


@sio.on("connect_error")
def connect_error(data):
    print("\nThe connection failed!")
    print(data["message"])
    print(data["data"]["content"])


@sio.on("request_sig")
def request_sig(data):
    print("\nReceived request_sig:", data)
    sig = ecc.sign(privKey, sio.get_sid() + data)
    sk = SigningKey.from_string(bytearray.fromhex(hex(privKey)[2:]), curve=SECP256k1)
    vk = VerifyingKey.from_string(bytearray.fromhex(pubKey_c[2:]), curve=SECP256k1)
    sig = sk.sign(
        (sio.get_sid() + data).encode("UTF-8"),
        hashfunc=hashlib.sha256,
        sigencode=ecdsa.util.sigencode_der_canonize,
    )
    sio.emit("response_sig", {"sig": sig, "pubKey_pem": vk.to_pem()})


@sio.on("authentication_success")
def authentication_success():
    pass


@sio.on("authentication_error")
def authentication_error():
    print("\nAuthentication error!")
    sys.exit(1)


@sio.on("start_ECDH")
def start_ECDH(data):
    print("\nReceived start_ECDH:")
    global A_sig
    A_sig = data["id_A"] + sio.get_sid() + data["pubKey_A"] + pubKey_c
    global A_pub
    A_pub = data["pubKey_A"]
    sio.emit(
        "responseB_ECDH",
        {
            "B_id": sio.get_sid(),
            "pubKey_B": pubKey_c,
            "sig": str(
                ecc.sign(
                    privKey, data["id_A"] + sio.get_sid() + data["pubKey_A"] + pubKey_c
                )
            ),
        },
    )


@sio.on("startA_ECDH")
def startA_ECDH(data):
    message = sio.get_sid() + data["id_B"] + pubKey_c + data["pubKey_B"]
    data["sig"] = [int(i) for i in data["sig"][1:-1].split(", ")]
    if not ecc.verify(message, data["sig"], data["pubKey_B"]):
        print("\nECDH error!")
        sio.disconnect()

    sio.emit(
        "responseA_ECDH",
        {
            "A_id": sio.get_sid(),
            "sig": str(
                ecc.sign(
                    privKey, sio.get_sid() + data["id_B"] + pubKey_c + data["pubKey_B"]
                )
            ),
        },
    )
    global shared_key
    shared_key = ecc.reconstruct_pubkey(data["pubKey_B"]) * privKey
    # print("\nShared key:", shared_key)
    print("Shared key established.")
    global flag
    flag = True


@sio.on("finalB_ECDH")
def finalB_ECDH(data):
    data["sig"] = [int(i) for i in data["sig"][1:-1].split(", ")]
    if not ecc.verify(A_sig, data["sig"], A_pub):
        print("\nECDH error!")
        sio.disconnect()
    global shared_key
    shared_key = ecc.reconstruct_pubkey(A_pub) * privKey
    # print("\nShared key:", shared_key)
    print("Shared key established.")
    global flag
    flag = True


@sio.on("recv_message")
def recv_message(data):
    cipher = AES.new(key, AES.MODE_EAX, nonce=data["nonce"])
    plaintext = cipher.decrypt(data["ciphertext"])
    try:
        cipher.verify(data["tag"])
        print(f"""{data["username"]}: {plaintext.decode("UTF-8")}""")
    except ValueError:
        print("Key incorrect or message corrupted")
        sio.disconnect()
        sys.exit(1)


@sio.event
def message(msg_txt):
    print("Server:", msg_txt)
    # sio.emit("my response", {"response": "my response"})


@sio.event
def disconnect():
    print("Disconnected from server")


def main():
    print(
        """  _____ ____  _____ _____     ___ __  __ 
 | ____|___ \| ____| ____|   |_ _|  \/  |
 |  _|   __) |  _| |  _| _____| || |\/| |
 | |___ / __/| |___| |__|_____| || |  | |
 |_____|_____|_____|_____|   |___|_|  |_|"""
    )

    # Prompt user for username
    username = input("Please enter your username: ")

    # Start loading animation
    print("Connecting to server...")

    # Connect to server
    try:
        sio.connect(
            "http://localhost:8080",
            auth={
                "username": username,
                "pubKey_pem": VerifyingKey.from_string(
                    bytearray.fromhex(pubKey_c[2:]), curve=SECP256k1
                )
                .to_pem()
                .decode("UTF-8"),
                "pubKey_c": pubKey_c,
            },
        )
    except socketio.exceptions.ConnectionError as e:
        sys.exit(1)

    print("\nClient authentication successful!")

    # Wait for other client to connect
    print("Waiting for other client to connect...")

    while flag == False:
        time.sleep(2)

    # shared_key = None
    global key
    key = hashlib.sha3_256(str(shared_key.x).encode("UTF-8")).digest()

    # Generate AES key
    cipher = AES.new(key, AES.MODE_EAX)

    # Prompt user for message
    print("\nType your message and press enter to send it.")

    while True:
        msg = input()
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(msg.encode("UTF-8"))
        sio.emit(
            "send_message",
            {
                "username": username,
                "ciphertext": ciphertext,
                "nonce": nonce,
                "tag": tag,
            },
        )


main()
