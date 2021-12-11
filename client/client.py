import sys
import base64
import hashlib
import os.path
import socketio
import ecdsa.util

from ecdsa import SigningKey, VerifyingKey, SECP256k1
from ecc import Secp256r1


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
    print("\nAuthentication successful!")


@sio.on("authentication_error")
def authentication_error():
    print("\nAuthentication error!")
    sys.exit(1)

# A_sig = None
# A_pub = None

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
            "sig": str(ecc.sign(
                privKey, data["id_A"] + sio.get_sid() + data["pubKey_A"] + pubKey_c
            )),
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
            "sig": str(ecc.sign(
                privKey,  sio.get_sid() + data["id_B"] + pubKey_c + data["pubKey_B"]
            )),
        },
    )

    shared_key = ecc.reconstruct_pubkey(data["pubKey_B"]) * privKey
    print("\nShared key:", shared_key)


@sio.on("finalB_ECDH")
def finalB_ECDH(data):
    data["sig"] = [int(i) for i in data["sig"][1:-1].split(", ")]
    if not ecc.verify(A_sig, data["sig"], A_pub):
        print("\nECDH error!")
        sio.disconnect()
    shared_key = ecc.reconstruct_pubkey(A_pub) * privKey
    print("\nShared key:", shared_key)

@sio.event
def message(msg_txt):
    print("Server:", msg_txt)
    # sio.emit("my response", {"response": "my response"})


@sio.event
def disconnect():
    print("Disconnected from server")


if __name__ == "__main__":
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

    # Wait for other client to connect
    sio.wait()
    print("Waiting for other client to connect...")

    # Send username and keypair to server
    # sio.emit("login", {"username": username, "pubKey_c": pubKey_c})

    sio.send("Hello World")
    sio.wait()
