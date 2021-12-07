import secrets 
import mock_key_builder.py # I am using this to create mock keys 
from ecc.py import Secp256r1


A = aliceh72gsb320000udocl363eofy

B = bobh72gsb320000udocl363eofy

#ecc = Secp256r1()


class Client:
    """
    NOTE: the class is written from the stand-point of alice and assuming that the other client is "bob" despite 
    the other client just being another instance of "alice
    """

    #we need a instance of ecc to do the gen gen?
    ecc = Secp256r1()
    def __init__(self,c):

        self.CUID = c
        pk_a = ecc.generate_private_key() 
        sk_a = ecc.generate_public_key(pk_a)
        #we are assuming that the Clinet knows g without needing to talk to the server
        g = ecc.g
        #we don't need a p becuase it is not applicable to the ecc version of diffie_hellamn 

    #the information about the other Client that we will need to authenticate
    pk_b = None
    sk_b = None
    CUID_b = None
    
    #this is the end goal of ecc_dh 
    symmetric_key = None


    def initiate(self);
        """
        this is step 1 in the diagram
        initaite is the first message in diffie_hellan

        input: none
        output: a python list of the classes CUID and their pk (public key)
        """
        inital_message = [self.CUID,self.pk_a]
        return return_list #return or send to the server to send to bob
    
    def response(self):
        """
        this is step 3 and 6 in the diagram
        this can either be the responce to the initate or to the response of bob

        output:
            responce_list = [CUID,pk,sign_sk(A,B,Pk_a,pk_b)
        """
        if B = None or pk_b = None:
            print("error in response function of,  ",CUID,"other client has not made contact yet")

        responce_list = [self.CUID,self.B,self.pk_a,self.pk_b]
        return responce_list


    def varify_person_with_server(self):
        """
        this is step 2 and 4 in diagram
        ask the db in on the server if the CUID of the other person matches their public key
        """
        if B = None or pk_b = None:
            print("error in response function of,  ",CUID,"other client has not made contact yet")

        return True #dummy true value until we figure it out

    def varify_signed(self):

        #I how will this be done?
        return True #dummy true value until we figure it out

    def calcualte_symmetric_key(self):
        
        return Null


#end of class Client 
#=============================================================================


main():
    alice = Client(A)
    bob = Client(B)

    server_dict = {"alice": A, "bob": B} #the server is the "authority" that each person is really who they say they are 

    #step 1 started by alice 
    message1_list = alice.initiate()
    bob.B = message1_list[0]
    bob.pk_b = message1_list[1]

    #step 2 bob
    is_alice = bob.varify_signed()

    if is_alice == True:
        message2_list = bob.response() #this is step 3
    else:
        print("alice is not who shes says she is")

    #step 4
    alice.B = message2_list[0]
    alice.pk_b = message2_list[3]

    is_bob = alice.varify_signed()
    if is_bob== True:
        alice.varify_signed()
    else:
        print("alice is not who shes says she is")















