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
        self.sk_a,self.pk_a = self.ecc.generate_keypair() #note that the pubic key is a hashed public key
        self.g = self.ecc.g

        self.pk_b = None
        self.CUID_b = None
        self.sign_sk_b = None #I really don't need to save 

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
            responce_list = [CUID,pk,sign_sk(A,B,Pk_a,pk_b) where:
            CUID: is alices "name"
            pk: alices privet key
            sign_sk = is a tuple of (r,s) where:
             is the x coordinate of a random point
                r is a random point's x (x,y); this random point in field is calculated with g and a random number k
                s: is a number calculated with current client's private key, k, r and other stuff in the field

                
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
        message = str(str_CUID_b + str_CUID + str_pk_b + str_pk_a) #note the switching of vars between sign and varify 
        signed_sk_x = self.ecc.sign(self.sk_a,message)


        responce_list = [self.pk_a,signed_sk_x]
        return responce_list



    def varify_person_with_server(self):
        """
        this is step 2 and 4 in diagram
        ask the db in on the server if the CUID of the other person matches their public key
        """
        if self.CUID_b == None or self.pk_b == None:
            print("error in response function of,  ",str(self.CUID_b),"other client has not made contact yet")

        return True #dummy true value until we figure it out

    def varify_signed(self,signature):
        """
        this function is used in step 5 and 7 
        this outputs a boolian value
        """
        
        str_CUID = str(self.CUID)
        str_CUID_b = str(self.CUID_b)
        str_pk_b = str(self.pk_b)
        str_pk_a = str(self.pk_a)
        message = str(str_CUID + str_CUID_b + str_pk_a + str_pk_b)
        return self.ecc.verify(message,signature,self.pk_b)


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
    bob = Client(B)
    
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



    #step 1 started by alice===================================================
    message1_list = alice.initiate()
    bob.CUID_b = message1_list[0]
    bob.pk_b = message1_list[1]

    print("===========================")
    print("check that message 1 worked")
    print("bobs copy of alices A",bob.CUID_b)
    print("bobs copy of alices pk",bob.pk_b)

    #step 2 bob needs to check with the server that alice is really alice======
    is_alice = bob.varify_person_with_server()

    if is_alice == True:
        print("ALICE IS ALICE")
        #message2_list = bob.response() #this is step 3
    else:
        print("alice is not who shes says she is")
    
    #step 3====================================================================
    response_1_output_list = bob.response_1()
    print("===========================")
    print("check that response 1 worked")
    print("response list 1",response_1_output_list)
    signed_sb = response_1_output_list[-1]
    #print("signed_sb",signed_sb)
    #step 4: varify bob is bob=================================================
    is_bob = alice.varify_person_with_server()

    print("===========================")
    if is_bob == True:
        print("BOB IS BOB")
            #message2_list = bob.response() #this is step 3
    else:
        print("bob is not who shes says she is")

    #step 5: varify signed message from bob====================================
    print("===========================")
    if alice.varify_signed(signed_sb)== True:
        print("bobs signed message is valid")
    else:
        print("bobs signed message is invalid")

    """
    #step 6: alice messages bob back with her info and signed keys=============
    response_2_output_list = bob.response_2()
    print("check that response 1 worked")
    print("response list 2",response_2_output_list)

    #step 7:varify signed message from alice===================================
    if alice.sign_sk_b == True:
        print("bobs signed message is valid")
    """


main()
