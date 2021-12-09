import secrets 
#import mock_key_builder.py # I am using this to create mock keys 
from ecc import Secp256r1
from ecc import Point


#ecc = Secp256r1()


class Client:
    """
    NOTE: the class is written from the stand-point of alice and assuming that the other client is "bob" despite 
    the other client just being another instance of "alice
    """

    #we need a instance of ecc to do the gen gen?
    def __init__(self,c):

        self.ecc = Secp256r1()
        self.CUID = c
        self.sk_a = self.ecc.generate_private_key() 
        self.pk_a = self.ecc.generate_public_key(self.sk_a)
        #we are assuming that the Clinet knows g without needing to talk to the server

        self.g = self.ecc.g
        self.pk_b = None
        self.CUID_b = None
        #this is the end goal
        self.symmetric_key = None


    def initiate(self):
        """
        this is step 1 in the diagram
        initaite is the first message in diffie_hellan

        input: none
        output: a python list of the classes CUID and their pk (public key)
        """
        inital_message = [self.CUID,self.pk_a]
        return inital_message
    
    def response_1(self):
        """
        this is step 3 in the diagram 

        output:
            responce_list = [CUID,pk,sign_sk(A,B,Pk_a,pk_b)
        """
        if self.CUID_b == None or self.pk_b == None:
            print("error in response function of,  ",self.CUID_b,"other client has not made contact yet")
            return None 
        str_CUID = str(self.CUID)
        str_CUID_b = str(self.CUID_b)
        str_pk_b = str(self.pk_b)
        str_pk_a = str(self.pk_a)
        message = str(str_CUID + str_CUID_b + str_pk_b + str_pk_a)
        signed_sk_x = self.ecc.sign(self.sk_a,message)


        responce_list = [self.CUID,self.pk_a,signed_sk_x]
        return responce_list

    def response_2(self):

        """
        this is step 3 in the diagram 

        output:
            responce_list = [CUID,pk,sign_sk(A,B,Pk_a,pk_b)
        """
        if self.CUID_b == None or self.pk_b == None:
            print("error in response function of,  ",self.CUID_b,"other client has not made contact yet")
            return None 
        str_CUID = str(self.CUID)
        str_CUID_b = str(self.CUID_b)
        str_pk_b = str(self.pk_b)
        str_pk_a = str(self.pk_a)
        message = str(str_CUID + str_CUID_b + str_pk_b + str_pk_a)
        signed_sk_x = self.ecc.sign(self.sk_a,message)


        responce_list = [self.pk_a,signed_sk_x]
        return responce_list



    def varify_person_with_server(self):
        """
        this is step 2 and 4 in diagram
        ask the db in on the server if the CUID of the other person matches their public key
        """
        if self.CUID_b == None or self.pk_b == None:
            print("error in response function of,  ",self.CUID_b,"other client has not made contact yet")

        return True #dummy true value until we figure it out

    def varify_signed(self,message,public_key,pk_b):
        self.ecc.verify()


        #I how will this be done?
        return True #dummy true value until we figure it out

    def calcualte_symmetric_key(self):
        
        return Null


#end of class Client 
#=============================================================================


def main():
    print("start main")
    A = "aliceh72gsb320000udocl363eofy"
    B = "bobh72gsb320000udocl363eofy"
    server_dict = {"alice": A, "bob": B} #the server is the "authority" that each person is really who they say they are 

    alice = Client(A)
    
    #check that substantiation worked
    #print(alice.pk_a)
    #print(alice.sk_a)
    #print(alice.g)
    #print(alice.CUID)
    #print("===========================")
    #print(alice.pk_b)
    #print(alice.CUID_b)
    #print(alice.g)
    #print(alice.symmetric_key)

    bob = Client(B)


    #step 1 started by alice 
    message1_list = alice.initiate()
    bob.CUID_b = message1_list[0]
    bob.pk_b = message1_list[1]

    print("===========================")
    print("check that message 1 worked")
    print("bobs copy of alices A",bob.CUID_b)
    print("bobs copy of alices pk",bob.pk_b)

    #step 2 bob needs to check with the server that alice is really alice 
    is_alice = bob.varify_person_with_server()

    if is_alice == True:
        print("ALICE IS ALICE")
        #message2_list = bob.response() #this is step 3
    else:
        print("alice is not who shes says she is")
    
    #step 3
    response_1_output_list = bob.response_1()
    print("===========================")
    print("check that response 1 worked")
    print("response list 1",response_1_output_list)
    """

    #step 4: varify bob is bob

    #step 5: varify signed message from bob

    """
    #step 6: alice messages bob back with her info and signed keys
    response_2_output_list = bob.response_2()
    print("check that response 1 worked")
    print("response list 2",response_2_output_list)

    #step 7:

main()
