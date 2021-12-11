import ecc_authenticated_diffie_hellman as dh
import ecc
import secrets
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend



def login_process(usernames, clients):
    while (len(usernames)<2):
        # Prompt user for username
        username = input("Please enter your username: ")
        # Start loading animation
        print("Connecting to server...")
        if username in usernames:
            print("User already exists:", username)
            pubK = input("Please enter your public key:")
            if pubK != usernames[username]:
                print("Authentication error: public key does not match user!")
                print("Please try another username.")
            else:
                verification = ecc.Secp256r1()
                print("Generate random token...")
                token = os.urandom(32)
                print('Your token is:', token)
                r,s = input('Please sign this token:').split()
                #signature = clients[username].ecc.sign(privKey, token)
                #print("signature is:", signature)
                print("Received signature from client...")
                sign = verification.verify(str(token), (int(r),int(s)), pubK)
                if not sign:
                    print("Authentication error: signature does not match user!")
                    print("Please try another username.")
                else:
                    print("You're already log in now.")
        else:
            print("Adding new user:", username)
            print( username , "informations:")
            user_CUID = username+"h72gsb320000udocl363eofy"
            print('CUID:',user_CUID)
            alice = dh.Client(user_CUID)
            usernames[username] = alice.pk_a
            clients[username] = alice
    print("There're two users connected to server now.")
    return(usernames, clients)

def DH(alice,bob,u_1,u_2):

    #step 1 started by alice===================================================
    response = input("For each client, there're local helper functions to help them sign, verify signature and calculate the shared key. Enter 0 if you just wanna see the simulation, and sent your public key and CUID to the other client otherwise: ")
    if response == '0':
        message1_list = alice.initiate()
        print(u_1,"'s message should be:", message1_list)
    else:
        message1_list = response.split()
    
    print("===========================")
    print( u_1, "starts the diffie hellman process with you. This is their CUID and public key: ")
    bob.CUID_b = message1_list[0]
    bob.pk_b = message1_list[1]
    
    #step 2 bob needs to check with the server that alice is really alice======
    is_alice = bob.varify_person_with_server()
    print("Verifying this user's identity...")
    if is_alice == True:
        print( u_1, " IS ", u_1)
        #message2_list = bob.response() #this is step 3
    else:
        print(u_1, " is not who they says they is")
    
    #step 3====================================================================
    if response == '0':
        response_1_output_list = bob.response_1()
        print(u_2,"'s response should be:", response_1_output_list)
    else:
        response_1_output_list = input("Enter your CUID, public key and signature: ").split()
    
    alice.signed_sk_b = response_1_output_list[-1]
    alice.CUID_b = response_1_output_list[0]
    alice.pk_b = response_1_output_list[1]
    
    #step 4: varify bob is bob=================================================
    print("===========================")
    print("Verifying this user's identity...")
    is_bob = alice.varify_person_with_server()
    print("===========================")
    if is_bob == True:
        print(u_2," IS ", u_2)
            #message2_list = bob.response() #this is step 3
    else:
        print(u_2, " is not who they says they is")

    #step 5: varify signed message from bob====================================
    if response == '0':
        print("===========================")
        if alice.varify_signed_response_1(alice.signed_sk_b) == True: 
            print(u_2, "'s signed message is valid")
        else:
            print(u_2, "'s signed message is invalid")
    
    #step 6: alice messages bob back with her info and signed keys=============
    print("===========================")
    if response == '0':
        response_2_output_list = alice.response_2()
        print(u_1,"'s response should be:", response_2_output_list)
    else:
        response_2_output_list = input("Enter your CUID and signature: ").split()
    
    #step 7:varify signed message from alice===================================
    bob.signed_sk_b = response_2_output_list[-1]
    bob.pk_b = response_2_output_list[0]
    if response == '0':
        print("===========================")
        if bob.varify_signed_response_2(bob.signed_sk_b) == True: #need to figure out how I want to deal with storing sign_sk_b
            print(u_1,"'s signed message is valid")
        else:
            print(u_1,"'s signed message is invalid")
    
    # each calculate their symmetric key 
    print("===========================")
    if response == '0':
        shared_key = alice.calcualte_symmetric_key()
        print(u_1 ,"calculated the key as:", shared_key)
        print(u_2 ,"calculated the key as:", bob.calcualte_symmetric_key())
    
    return(response, shared_key)
"""
def convert_shared_key_to_bytes(key):
    Key_c = str(2 + key.y % 2) + str(hex(key.x)[2:])
    key_b = int(Key_c,16).to_bytes(32,'big')
    return key_b
"""
def main():
    print(
        """  _____ ____  _____ _____     ___ __  __ 
 | ____|___ \| ____| ____|   |_ _|  \/  |
 |  _|   __) |  _| |  _| _____| || |\/| |
 | |___ / __/| |___| |__|_____| || |  | |
 |_____|_____|_____|_____|   |___|_|  |_|"""
    )

    usernames = {}
    clients = {}


    usernames, clients = login_process(usernames, clients)
    
    
    print("===========================")
    u_1 = input("Enter your user name if you want to initialize the diffie hellman process with the other client: ")
    alice = clients[u_1]
    for i in clients:
        if i != u_1:
            u_2 = i
            bob = clients[i]

    response, shared_key = DH(alice,bob,u_1,u_2)
    print("===========================")
    
    
    if response == '0':
        backend = default_backend()
        #while(len(clients)>1):
        message = input("Now enter message you wanna sent, and we'll show the encrypetd message that will sent to the other client.")          
        """"
        iv = os.urandom(16)
        shared_key_b = convert_shared_key_to_bytes(shared_key)
        cipher = Cipher(algorithms.AES(shared_key_b), modes.CBC(iv), backend=backend)
        encryptor = cipher.encryptor()
        ct = encryptor.update(b"a secret message") + encryptor.finalize()
        decryptor = cipher.decryptor()
        decryptor.update(ct) + decryptor.finalize()
        """


    



main()